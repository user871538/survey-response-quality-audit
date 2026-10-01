#!/usr/bin/env python3
"""Audit the supplied fictional meal-kit survey. Python 3.9+, standard library only.

Run: python audit_survey.py survey_responses.csv --output audit_results
Optional: --answer-key answer_key.csv (read AFTER rules and outputs are fixed).
This implements a transparent exercise policy, not a validated fraud classifier.
"""
import argparse
import csv
import hashlib
import json
import math
import re
import statistics
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from pathlib import Path

PAGES = ['screener', 'behaviour', 'customer', 'attitudes', 'concept', 'text', 'final']
RATINGS = ['rating_' + s for s in ['value', 'convenience', 'variety', 'freshness', 'portion_size', 'packaging']]
ATTITUDES = ['attitude_' + s for s in ['enjoy_cooking', 'plan_meals', 'seek_variety', 'watch_spending', 'value_convenience', 'reduce_waste', 'dislike_planning', 'prefer_repetition']]
PAGE_ITEMS = {
    'screener': ['consent', 'age_years', 'gender', 'residence_country', 'region', 'household_size', 'income_band'],
    'behaviour': ['current_mealkit_customer', 'purchased_mealkit_3m', 'mealkit_boxes_3m', 'weekly_grocery_spend_gbp', 'first_mealkit_year'],
    'customer': ['overall_satisfaction', 'recommend_0_10'],
    'attitudes': RATINGS + ATTITUDES + ['attention_colour'],
    'concept': ['purchase_intent', 'willingness_to_pay_gbp', 'attention_number'],
    'text': ['reason_open', 'improvement_open'], 'final': []
}
RANGES = {
    'consent': (0, 1), 'age_years': (0, 120), 'household_size': (1, 20),
    'current_mealkit_customer': (0, 1), 'purchased_mealkit_3m': (0, 1),
    'mealkit_boxes_3m': (0, 100), 'customer_page_displayed': (0, 1),
    'first_mealkit_year': (1900, 2026), 'overall_satisfaction': (1, 5),
    'recommend_0_10': (0, 10), 'attention_number': (1, 4), 'purchase_intent': (1, 5),
    **{f: (1, 5) for f in RATINGS + ATTITUDES},
    **{f'page_{p}_seconds': (0, math.inf) for p in PAGES},
    'duration_seconds': (0, math.inf), 'weekly_grocery_spend_gbp': (0, math.inf),
    'willingness_to_pay_gbp': (0, math.inf)
}
CONTINUOUS = {'weekly_grocery_spend_gbp', 'willingness_to_pay_gbp'}
CATEGORIES = {
    'gender': {'woman', 'man', 'nonbinary', 'prefer_not_to_say'},
    'region': {'England', 'Scotland', 'Wales', 'Northern Ireland', 'Outside UK'},
    'income_band': {'under_25000', '25000_to_49999', '50000_to_74999', '75000_plus', 'prefer_not_to_say'},
    'device_type': {'mobile', 'desktop', 'tablet'},
    'recruitment_source': {'panel_a', 'panel_b', 'social_ad'},
    'survey_version': {'v1.0', 'v1.1'}, 'survey_language': {'en-GB'},
    'response_status': {'complete', 'partial'}, 'last_page': set(PAGES),
    'attention_colour': {'blue', 'gold', 'green', 'silver'}
}
DEFINITIONS = {
    'ineligible': ('eligibility', 'Observed consent, age or country fails the target screen.'),
    'eligibility_unknown': ('eligibility', 'One or more screening fields are missing or invalid.'),
    'duplicate_group': ('duplicates', 'Shared person ID within source or invitation token; review all group members.'),
    'duplicate_secondary': ('duplicates', 'Additional group submission under earliest-start retention policy.'),
    'shared_ip': ('duplicates', 'IP shared with other submissions; informational only.'),
    'shared_device': ('duplicates', 'Device shared; informational unless corroborated.'),
    'identical_answer_vector': ('duplicates', 'Complete substantive answer vector repeated; informational only.'),
    'required_missing': ('completeness', 'Required items blank on pages the session reached.'),
    'breakoff': ('completeness', 'Partial status or final page not reached.'),
    'speeding_total': ('speed', 'Duration below configurable fraction of matched-route/device median.'),
    'speeding_pages': ('speed', 'At least three reached pages below their peer timing thresholds.'),
    'long_duration': ('timing', 'Duration over five times matched median; informational pause indicator.'),
    'uniform_ratings': ('patterns', 'All six offer attribute ratings identical; review, not automatic rejection.'),
    'uniform_attitudes': ('patterns', 'All eight attitude answers identical.'),
    'alternating_attitudes': ('patterns', 'All eight attitude answers alternate between two different values.'),
    'reverse_item_tension': ('consistency', 'Both opposite-worded pairs deviate from complementary scores by at least three points; soft evidence.'),
    'attention_failure': ('attention', 'At least one reached attention question has an incorrect, nonmissing answer.'),
    'purchase_contradiction': ('consistency', 'No purchases reported alongside a positive three-month box count.'),
    'invalid_numeric': ('plausibility', 'Nonfinite, nonnumeric, noninteger or out-of-range numeric value.'),
    'invalid_category': ('plausibility', 'Code outside the documented questionnaire categories.'),
    'spending_outlier': ('plausibility', 'Valid spending exceeds Q3 + 3 IQR; informational only.'),
    'short_open_text': ('text', 'Fewer than three words in a nonmissing text answer; informational only.'),
    'low_relevance_text': ('text', 'Both nonmissing text answers lack topic vocabulary; heuristic review signal.'),
    'repeated_open_text': ('text', 'Same main-reason text appears in several submissions; informational only.'),
    'routing_fault': ('technical', 'Observed customer-page display disagrees with intended routing.'),
    'unexpected_answer': ('technical', 'Answer present for a structurally skipped or unreached question.'),
    'possible_intent_coding_fault': ('technical', 'v1.0 purchase intent is one of 10,20,30,40,50; verify coding before repair.'),
    'missing_timing_metadata': ('technical', 'Expected timestamp or duration missing.'),
    'invalid_timestamp': ('technical', 'Timestamp not parseable as timezone-aware ISO 8601.'),
    'timing_inconsistency': ('technical', 'Page sum, elapsed timestamps, status, or timestamp order disagree.'),
    'survey_metadata_fault': ('technical', 'Unknown page or status prevents reliable routing interpretation.')
}
INFORMATION_ONLY = {'shared_ip', 'shared_device', 'identical_answer_vector', 'long_duration',
                    'short_open_text', 'repeated_open_text', 'spending_outlier'}

@dataclass(frozen=True)
class Config:
    speed_fraction: float = .4
    exclude_domains: int = 2
    min_peer_group: int = 10
    require_complete: bool = False
    repair_intent_codes: bool = False

def number(value):
    try:
        n = float(value)
        return n if math.isfinite(n) else None
    except (ValueError, TypeError):
        return None

def timestamp(value):
    try:
        dt = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
        return dt if dt.utcoffset() is not None else None
    except (ValueError, TypeError):
        return None

def norm(text):
    return ' '.join(re.findall(r'[a-z0-9]+', str(text).lower()))

def read_csv(path):
    with Path(path).open(encoding='utf-8-sig', newline='') as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames or len(reader.fieldnames) != len(set(reader.fieldnames)):
            raise ValueError('Missing or duplicate column headers.')
        rows = list(reader)
        if any(None in r or any(v is None for v in r.values()) for r in rows):
            raise ValueError('Malformed CSV: row width does not match headers.')
        return rows, reader.fieldnames

def write_csv(path, rows, fields=None):
    rows = list(rows)
    fields = fields or (list(rows[0]) if rows else [])
    with Path(path).open('w', encoding='utf-8-sig', newline='') as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)

def require_schema(rows, headers):
    required = set(RANGES) | set(CATEGORIES) | {'response_id', 'respondent_id', 'invitation_token',
        'device_fingerprint', 'ip_address', 'started_at_utc', 'submitted_at_utc', 'last_activity_at_utc',
        'residence_country', 'reason_open', 'improvement_open'}
    missing = required - set(headers)
    if missing:
        raise ValueError('Missing required columns: ' + ', '.join(sorted(missing)))
    ids = [r['response_id'] for r in rows]
    if not rows or any(not i for i in ids) or len(ids) != len(set(ids)):
        raise ValueError('Input must contain records with nonblank unique response_id values.')

def reached(row, page):
    last = row.get('last_page')
    if last not in PAGES:
        return False
    return PAGES.index(page) <= PAGES.index(last)

def expected_fields(row):
    expected = []
    for p, items in PAGE_ITEMS.items():
        if not reached(row, p):
            continue
        if p == 'customer' and number(row['current_mealkit_customer']) != 1:
            continue
        for f in items:
            if f == 'improvement_open':
                continue
            if f == 'first_mealkit_year' and number(row['purchased_mealkit_3m']) != 1:
                continue
            expected.append(f)
    return expected

def quantile(values, fraction):
    if not values:
        return None
    s = sorted(values); pos = (len(s) - 1) * fraction
    lo = int(pos); hi = min(lo + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (pos - lo)

def long_run(values):
    best = current = 0; previous = None
    for v in values:
        if v is None:
            current = 0
        else:
            current = current + 1 if v == previous else 1
        best = max(best, current); previous = v
    return best

def group_indexes(rows, key):
    groups = defaultdict(list)
    for i, r in enumerate(rows):
        k = key(r)
        if k and (not isinstance(k, tuple) or all(k)):
            groups[k].append(i)
    return groups

def duplicate_map(rows):
    # Union overlapping strong identifiers to avoid retaining multiple anchors.
    parents = list(range(len(rows)))
    def find(i):
        while parents[i] != i:
            parents[i] = parents[parents[i]]; i = parents[i]
        return i
    for key in [lambda r: (r['recruitment_source'], r['respondent_id']), lambda r: r['invitation_token']]:
        for members in group_indexes(rows, key).values():
            for j in members[1:]:
                parents[find(j)] = find(members[0])
    groups = defaultdict(list)
    for i in range(len(rows)):
        groups[find(i)].append(i)
    result = {}
    for members in groups.values():
        if len(members) > 1:
            anchor = min(members, key=lambda i: (timestamp(rows[i]['started_at_utc']) or datetime.max.replace(tzinfo=timezone.utc), rows[i]['response_id']))
            for i in members:
                result[i] = (rows[anchor]['response_id'], i != anchor, len(members))
    return result

def audit(rows, config):
    duplicates = duplicate_map(rows)
    ip_counts = Counter(r['ip_address'] for r in rows if r['ip_address'])
    device_counts = Counter(r['device_fingerprint'] for r in rows if r['device_fingerprint'])
    text_counts = Counter(norm(r['reason_open']) for r in rows if norm(r['reason_open']))
    substantive = RATINGS + ATTITUDES + ['purchase_intent', 'willingness_to_pay_gbp', 'reason_open', 'improvement_open']
    vectors = Counter(tuple(r[f] for f in substantive) for r in rows)
    total_groups = defaultdict(list); page_groups = defaultdict(list)
    for r in rows:
        # Timing reference: completed, eligible-looking sessions, valid positive duration.
        if r['response_status'] != 'complete' or r['last_page'] != 'final' or r['residence_country'] != 'UK' or number(r['consent']) != 1 or (number(r['age_years']) or 0) < 18:
            continue
        route = number(r['current_mealkit_customer'])
        n = number(r['duration_seconds'])
        if n is not None and n > 0:
            total_groups[(route, r['device_type'])].append(n)
            total_groups[(route, 'ALL')].append(n)
        for p in PAGES:
            n = number(r[f'page_{p}_seconds'])
            if n is not None and n > 0:
                page_groups[(p, r['device_type'])].append(n)
                page_groups[(p, 'ALL')].append(n)
    def median_for(groups, key, fallback):
        sample = groups.get(key, [])
        if len(sample) < config.min_peer_group:
            sample = groups.get(fallback, [])
        return statistics.median(sample) if len(sample) >= config.min_peer_group else None
    spend = [number(r['weekly_grocery_spend_gbp']) for r in rows]
    spend = [v for v in spend if v is not None and v >= 0]
    q1, q3 = quantile(spend, .25), quantile(spend, .75)
    outlier_cutoff = q3 + 3 * (q3 - q1) if spend else math.inf
    topic = re.compile(r'\b(meal\w*|cook\w*|food|recipe\w*|ingredient\w*|price\w*|cost\w*|expensive|cheap\w*|time|variety|portion\w*|packaging|plastic|recycl\w*|deliver\w*|vegetarian|allergen\w*|waste|shop\w*|convenien\w*|save\w*|lower|bigger)\b', re.I)
    results = []; cleaned = []
    for i, r in enumerate(rows):
        flags = {}; domains = set(); mask = set(); repairs = {}
        def flag(name, detail):
            flags[name] = detail
        def domain(name):
            domains.add(name)
        consent, age = number(r['consent']), number(r['age_years'])
        if consent == 0 or (age is not None and 0 <= age < 18) or (r['residence_country'] and r['residence_country'] != 'UK'):
            flag('ineligible', 'Target is consenting UK adults aged 18+.')
        elif consent != 1 or age is None or age < 0 or age > 120 or age != int(age) or not r['residence_country']:
            flag('eligibility_unknown', 'Missing/invalid target-screen information.')
        if i in duplicates:
            anchor, secondary, size = duplicates[i]
            flag('duplicate_group', f'{size} submissions; selected anchor={anchor}')
            if secondary:
                flag('duplicate_secondary', f'Earliest-start anchor={anchor}')
        else:
            anchor = ''; size = 1
        if ip_counts[r['ip_address']] > 1:
            flag('shared_ip', str(ip_counts[r['ip_address']]) + ' submissions share IP.')
        if device_counts[r['device_fingerprint']] > 1:
            flag('shared_device', str(device_counts[r['device_fingerprint']]) + ' submissions share device.')
        if vectors[tuple(r[f] for f in substantive)] > 1:
            flag('identical_answer_vector', 'Exact substantive vector shared; corroborate identifiers.')
        if r['last_page'] not in PAGES or r['response_status'] not in CATEGORIES['response_status']:
            flag('survey_metadata_fault', 'Unknown page/status; completeness checks are limited.')
        expected = expected_fields(r)
        missing = [f for f in expected if not r[f].strip()]
        if missing:
            flag('required_missing', ';'.join(missing))
        partial = r['response_status'] == 'partial' or r['last_page'] != 'final'
        if partial:
            flag('breakoff', 'Last page=' + r['last_page'])
        for f, (low, high) in RANGES.items():
            if not r[f].strip():
                continue
            n = number(r[f])
            if n is None or n < low or n > high or (f not in CONTINUOUS and n != int(n)):
                flag('invalid_numeric', flags.get('invalid_numeric', '') + f'{f}={r[f]};')
                mask.add(f)
        for f, allowed in CATEGORIES.items():
            if r[f] and r[f] not in allowed:
                flag('invalid_category', flags.get('invalid_category', '') + f'{f}={r[f]};')
                mask.add(f)
        if number(r['weekly_grocery_spend_gbp']) is not None and number(r['weekly_grocery_spend_gbp']) > outlier_cutoff:
            flag('spending_outlier', f'Above exploratory cutoff {outlier_cutoff:.2f} GBP.')
        intended_customer = number(r['current_mealkit_customer']) == 1 and reached(r, 'customer')
        observed_customer = number(r['customer_page_displayed'])
        if observed_customer is not None and observed_customer != int(intended_customer):
            flag('routing_fault', f'Expected customer page={int(intended_customer)}, observed={observed_customer}.')
            if not intended_customer:
                mask.update(PAGE_ITEMS['customer'])
        for p, items in PAGE_ITEMS.items():
            for f in items:
                should_show = reached(r, p) and (p != 'customer' or intended_customer)
                if f == 'first_mealkit_year':
                    should_show = should_show and number(r['purchased_mealkit_3m']) == 1
                if r[f] and not should_show:
                    flag('unexpected_answer', flags.get('unexpected_answer', '') + f + ';')
                    mask.add(f)
        n = number(r['purchase_intent'])
        if r['survey_version'] == 'v1.0' and n in {10, 20, 30, 40, 50}:
            flag('possible_intent_coding_fault', 'Verify version-specific code mapping before dividing by 10.')
            if config.repair_intent_codes and reached(r, 'concept'):
                repairs['purchase_intent'] = str(int(n / 10)); mask.discard('purchase_intent')
        if number(r['purchased_mealkit_3m']) == 0 and (number(r['mealkit_boxes_3m']) or 0) > 0:
            flag('purchase_contradiction', 'No purchases but positive box count.'); domain('logic')
            mask.update(['purchased_mealkit_3m', 'mealkit_boxes_3m'])
        fails = [f for p, f, correct in [('attitudes', 'attention_colour', 'silver'), ('concept', 'attention_number', '2')]
                 if reached(r, p) and r[f] and r[f] != correct]
        if fails:
            flag('attention_failure', ';'.join(fails)); domain('attention')
        rating_values = [number(r[f]) for f in RATINGS]
        attitude_values = [number(r[f]) for f in ATTITUDES]
        if all(v is not None and 1 <= v <= 5 for v in rating_values) and len(set(rating_values)) == 1:
            flag('uniform_ratings', 'Six identical attribute ratings.'); domain('pattern')
        if all(v is not None and 1 <= v <= 5 for v in attitude_values):
            if len(set(attitude_values)) == 1:
                flag('uniform_attitudes', 'Eight identical attitude ratings.'); domain('pattern')
            elif len(set(attitude_values)) == 2 and all(attitude_values[j] == attitude_values[j % 2] for j in range(8)):
                flag('alternating_attitudes', 'Two values alternate across all eight items.'); domain('pattern')
            if abs(attitude_values[1] + attitude_values[6] - 6) >= 3 and abs(attitude_values[2] + attitude_values[7] - 6) >= 3:
                flag('reverse_item_tension', 'Both opposite-worded pairs show strong tension.')
        short = [f for f in ['reason_open', 'improvement_open'] if r[f] and len(norm(r[f]).split()) < 3]
        if short:
            flag('short_open_text', ';'.join(short))
        if r['reason_open'] and r['improvement_open'] and not topic.search(r['reason_open']) and not topic.search(r['improvement_open']):
            flag('low_relevance_text', 'Both text answers lack topic terms; manual review needed.'); domain('text')
        if norm(r['reason_open']) and text_counts[norm(r['reason_open'])] >= 3:
            flag('repeated_open_text', f'{text_counts[norm(r["reason_open"])]} identical normalized reason texts.')
        required_times = ['started_at_utc', 'last_activity_at_utc', 'duration_seconds'] + [f'page_{p}_seconds' for p in PAGES] + ([] if partial else ['submitted_at_utc'])
        absent_times = [f for f in required_times if not r[f]]
        if absent_times:
            flag('missing_timing_metadata', ';'.join(absent_times))
        dates = {f: timestamp(r[f]) for f in ['started_at_utc', 'last_activity_at_utc', 'submitted_at_utc']}
        bad_dates = [f for f, dt in dates.items() if r[f] and dt is None]
        if bad_dates:
            flag('invalid_timestamp', ';'.join(bad_dates)); mask.update(bad_dates)
        duration = number(r['duration_seconds'])
        page_times = [number(r[f'page_{p}_seconds']) for p in PAGES]
        timing_errors = []
        if duration is not None and all(t is not None for t in page_times) and abs(sum(page_times) - duration) > 2:
            timing_errors.append('page_time_sum')
        endpoint = dates['last_activity_at_utc'] if partial else dates['submitted_at_utc']
        if dates['started_at_utc'] and endpoint:
            elapsed = (endpoint - dates['started_at_utc']).total_seconds()
            if elapsed < 0 or (duration is not None and abs(elapsed - duration) > 2):
                timing_errors.append('elapsed_timestamps')
        if dates['last_activity_at_utc'] and dates['submitted_at_utc'] and dates['submitted_at_utc'] < dates['last_activity_at_utc']:
            timing_errors.append('submission_before_last_activity')
        if partial and r['submitted_at_utc']:
            timing_errors.append('partial_with_submission')
        for p in PAGES:
            expected_page = reached(r, p) and (p != 'customer' or intended_customer)
            pt = number(r[f'page_{p}_seconds'])
            if not expected_page and pt is not None and pt > 0:
                timing_errors.append('unexpected_page_time:' + p)
        if timing_errors:
            flag('timing_inconsistency', ';'.join(timing_errors))
        median = median_for(total_groups, (number(r['current_mealkit_customer']), r['device_type']), (number(r['current_mealkit_customer']), 'ALL'))
        ratio = duration / median if duration is not None and median and duration >= 0 else None
        # Total-speed check only compares full-route complete sessions.
        if not partial and ratio is not None and 'timing_inconsistency' not in flags and 'duration_seconds' not in mask:
            if ratio < config.speed_fraction:
                flag('speeding_total', f'Duration/peer median={ratio:.3f}'); domain('speed')
            if ratio > 5:
                flag('long_duration', f'Duration/peer median={ratio:.3f}')
        fast_pages = []
        for p in PAGES:
            pt = number(r[f'page_{p}_seconds'])
            med = median_for(page_groups, (p, r['device_type']), (p, 'ALL'))
            if reached(r, p) and (p != 'customer' or intended_customer) and pt is not None and pt >= 0 and med and pt < config.speed_fraction * med:
                fast_pages.append(p)
        if len(fast_pages) >= 3 and 'timing_inconsistency' not in flags:
            flag('speeding_pages', ';'.join(fast_pages)); domain('speed')
        if 'ineligible' in flags:
            decision = 'exclude_ineligible'
        elif 'eligibility_unknown' in flags:
            decision = 'hold_eligibility_review'
        elif 'duplicate_secondary' in flags:
            decision = 'exclude_duplicate'
        elif len(domains) >= config.exclude_domains:
            decision = 'exclude_multiple_behaviour_signals'
        elif config.require_complete and (partial or missing):
            decision = 'exclude_incomplete'
        elif mask or repairs:
            decision = 'retain_with_field_changes'
        elif set(flags) - INFORMATION_ONLY:
            decision = 'retain_with_review_flags'
        else:
            decision = 'retain'
        keep = decision.startswith('retain')
        clean = dict(r)
        for f in mask:
            clean[f] = ''
        clean.update(repairs)
        if keep:
            cleaned.append(clean)
        results.append({
            'response_id': r['response_id'], 'decision': decision, 'retained': int(keep),
            'quality_flag_count': len(set(flags) - INFORMATION_ONLY),
            'behaviour_domain_count': len(domains), 'behaviour_domains': ';'.join(sorted(domains)),
            'required_item_count': len(expected), 'required_missing_count': len(missing),
            'required_missing_fraction': round(len(missing) / len(expected), 4) if expected else '',
            'peer_median_duration_seconds': median if median is not None else '',
            'duration_to_peer_median': round(ratio, 4) if ratio is not None else '',
            'fast_page_count': len(fast_pages), 'attitude_longest_run': long_run(attitude_values),
            'duplicate_anchor_response_id': anchor, 'duplicate_group_size': size,
            'masked_fields': ';'.join(sorted(mask)), 'repaired_fields': ';'.join(sorted(repairs)),
            'flags': ';'.join(sorted(flags)), 'flag_details_json': json.dumps(flags, sort_keys=True),
            **{'flag_' + name: int(name in flags) for name in DEFINITIONS}
        })
    return results, cleaned

def safe_mean(values):
    return statistics.mean(values) if values else None

def pearson(pairs):
    if len(pairs) < 3:
        return None
    xs, ys = zip(*pairs); mx, my = statistics.mean(xs), statistics.mean(ys)
    denom = math.sqrt(sum((x - mx)**2 for x in xs) * sum((y - my)**2 for y in ys))
    return sum((x - mx) * (y - my) for x, y in pairs) / denom if denom else None

def outcome_metrics(rows):
    metrics = []
    for f in ['purchase_intent', 'willingness_to_pay_gbp', 'overall_satisfaction']:
        eligible_rows = [r for r in rows if f != 'overall_satisfaction' or number(r['current_mealkit_customer']) == 1]
        values = [number(r[f]) for r in eligible_rows]
        values = [v for v in values if v is not None]  # Raw intentionally includes invalid numeric codes.
        metrics.append({'metric': 'mean_' + f, 'n_valid': len(values), 'n_cohort': len(eligible_rows), 'value': safe_mean(values)})
        if f == 'purchase_intent':
            metrics.append({'metric': 'purchase_intent_4_or_5_pct', 'n_valid': len(values), 'n_cohort': len(eligible_rows),
                            'value': 100 * sum(v in {4, 5} for v in values) / len(values) if values else None})
    pairs = [(number(r['attitude_value_convenience']), number(r['purchase_intent'])) for r in rows]
    pairs = [(x, y) for x, y in pairs if x is not None and y is not None]
    metrics.append({'metric': 'pearson_convenience_purchase_intent', 'n_valid': len(pairs), 'n_cohort': len(rows), 'value': pearson(pairs)})
    return metrics

def composition_value(row, field):
    if field != 'age_group':
        return row[field] or '(missing)'
    n = number(row['age_years'])
    if n is None or not 0 <= n <= 120:
        return '(missing_or_invalid)'
    return 'under_18' if n < 18 else '18_34' if n < 35 else '35_54' if n < 55 else '55_plus'

def composition(rows, cleaned):
    out = []
    for f in ['age_group', 'gender', 'device_type', 'recruitment_source', 'survey_version']:
        raw = Counter(composition_value(r, f) for r in rows)
        clean = Counter(composition_value(r, f) for r in cleaned)
        for group in sorted(raw.keys() | clean.keys()):
            a = 100 * raw[group] / len(rows)
            b = 100 * clean[group] / len(cleaned) if cleaned else None
            out.append({'variable': f, 'group': group, 'raw_n': raw[group], 'retained_n': clean[group],
                        'raw_pct': a, 'retained_pct': b, 'change_percentage_points': b - a if b is not None else None,
                        'exclusion_rate_pct': 100 * (raw[group] - clean[group]) / raw[group] if raw[group] else None})
    return out

def detection_metrics(actual, predicted):
    tp = sum(a and p for a, p in zip(actual, predicted)); fp = sum(not a and p for a, p in zip(actual, predicted))
    fn = sum(a and not p for a, p in zip(actual, predicted)); tn = sum(not a and not p for a, p in zip(actual, predicted))
    return {'n': len(actual), 'tp': tp, 'fp': fp, 'fn': fn, 'tn': tn,
            'precision': tp / (tp + fp) if tp + fp else None,
            'recall': tp / (tp + fn) if tp + fn else None,
            'false_positive_rate': fp / (fp + tn) if fp + tn else None}

def evaluate(rows, results, cleaned, answer_key):
    truth_rows, _ = read_csv(answer_key)
    if len({t.get('response_id') for t in truth_rows}) != len(truth_rows):
        raise ValueError('Answer key has repeated response IDs.')
    truth = {t['response_id']: t for t in truth_rows}
    required = {'record_quality_problem', 'respondent_quality_problem', 'eligible_truth', 'duplicate_of_response_id', 'reference_action',
                'scenario', 'true_purchase_intent', 'true_satisfaction', 'true_current_mealkit_customer', 'true_willingness_to_pay_gbp'}
    if not truth_rows or not required <= set(truth_rows[0]) or set(truth) != {r['response_id'] for r in rows}:
        raise ValueError('Answer key schema/response IDs do not exactly match input.')
    ts = [truth[r['response_id']] for r in rows]
    for t in ts:
        if any(t[f] not in {'0', '1'} for f in ['record_quality_problem', 'respondent_quality_problem', 'eligible_truth']):
            raise ValueError('Answer-key truth flags must be 0 or 1.')
    evaluations = []
    for name, target, predictions in [
        ('any_quality_flag', 'record_quality_problem', [r['quality_flag_count'] > 0 for r in results]),
        ('any_behaviour_domain', 'respondent_quality_problem', [r['behaviour_domain_count'] > 0 for r in results]),
        ('behaviour_exclusion', 'respondent_quality_problem', [r['decision'] == 'exclude_multiple_behaviour_signals' for r in results]),
        ('whole_record_exclusion_policy', None, [r['decision'].startswith('exclude') for r in results])]:
        actual = [t[target] == '1' if target else t['reference_action'].startswith('exclude') for t in ts]
        evaluations.append({'detector': name, 'truth_target': target or 'reference_action starts with exclude', **detection_metrics(actual, predictions)})
    scenario_rows = []
    for scenario in sorted({t['scenario'] for t in ts}):
        indexes = [i for i, t in enumerate(ts) if t['scenario'] == scenario]
        scenario_rows.append({'scenario': scenario, 'n': len(indexes),
            'quality_flagged_n': sum(results[i]['quality_flag_count'] > 0 for i in indexes),
            'excluded_n': sum(results[i]['decision'].startswith('exclude') for i in indexes),
            'held_n': sum(results[i]['decision'].startswith('hold') for i in indexes),
            'field_changes_n': sum(bool(results[i]['masked_fields'] or results[i]['repaired_fields']) for i in indexes)})
    clean_by_id = {r['response_id']: r for r in cleaned}
    target_cohort = [r for r in rows if truth[r['response_id']]['eligible_truth'] == '1' and not truth[r['response_id']]['duplicate_of_response_id']]
    benchmark = []
    for name, field, true_field in [('purchase_intent', 'purchase_intent', 'true_purchase_intent'),
                                   ('willingness_to_pay_gbp', 'willingness_to_pay_gbp', 'true_willingness_to_pay_gbp'),
                                   ('satisfaction', 'overall_satisfaction', 'true_satisfaction')]:
        cohort = [r for r in target_cohort if name != 'satisfaction' or truth[r['response_id']]['true_current_mealkit_customer'] == '1']
        for stage in ['raw', 'cleaned']:
            observed = []; matched_truth = []; full_truth = []
            for r in cohort:
                t = truth[r['response_id']]; true_value = number(t[true_field])
                if true_value is not None:
                    full_truth.append(true_value)
                source = r if stage == 'raw' else clean_by_id.get(r['response_id'])
                value = number(source[field]) if source else None
                if value is not None and true_value is not None:
                    observed.append(value); matched_truth.append(true_value)
            a, b, full = safe_mean(observed), safe_mean(matched_truth), safe_mean(full_truth)
            benchmark.append({'metric': name, 'stage': stage, 'n_observed_matched': len(observed), 'n_full_target': len(full_truth),
                'observed_mean': a, 'truth_mean_same_respondents': b, 'truth_mean_full_eligible_unique_cohort': full,
                'measurement_bias_same_respondents': a - b if a is not None and b is not None else None,
                'total_error_vs_full_target': a - full if a is not None and full is not None else None})
    return evaluations, scenario_rows, benchmark

def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def run(args):
    source = Path(args.input).resolve(); destination = Path(args.output).resolve()
    rows, headers = read_csv(source); require_schema(rows, headers)
    config = Config(args.speed_fraction, args.exclude_domains, args.min_peer_group, args.require_complete, args.repair_intent_codes)
    if not 0 < config.speed_fraction < 1 or config.exclude_domains < 1 or config.min_peer_group < 2:
        raise ValueError('Require 0<speed fraction<1, exclusion domains>=1, and peer group>=2.')
    destination.mkdir(parents=True, exist_ok=True)
    # Prevent raw input or answer key from being overwritten by result paths.
    output_names = ['respondent_audit.csv', 'cleaned_responses.csv', 'flag_summary.csv', 'flag_definitions.csv',
        'item_quality.csv', 'page_dropoff.csv', 'sample_composition.csv', 'outcome_comparison.csv',
        'technical_by_version.csv', 'sensitivity.csv', 'sensitivity_evaluation.csv', 'evaluation.csv', 'evaluation_by_scenario.csv',
        'truth_benchmarks.csv', 'run_manifest.json', 'audit_report.md']
    protected = {source} | ({Path(args.answer_key).resolve()} if args.answer_key else set())
    if any(destination / n in protected for n in output_names):
        raise ValueError('Output directory would overwrite an input file.')
    existing = [n for n in output_names if (destination / n).exists()]
    if existing and not args.overwrite:
        raise ValueError('Existing outputs found. Use a new directory or --overwrite.')
    if args.overwrite:
        # Remove stale OPTIONAL evaluation outputs from earlier labelled runs.
        for n in ['evaluation.csv', 'evaluation_by_scenario.csv', 'truth_benchmarks.csv', 'sensitivity_evaluation.csv']:
            (destination / n).unlink(missing_ok=True)
    results, cleaned = audit(rows, config)
    write_csv(destination / 'respondent_audit.csv', results)
    write_csv(destination / 'cleaned_responses.csv', cleaned, headers)
    write_csv(destination / 'flag_definitions.csv', [{'flag': n, 'criterion': c, 'definition': d, 'information_only': int(n in INFORMATION_ONLY)} for n, (c, d) in DEFINITIONS.items()])
    summary = [{'flag': n, 'criterion': DEFINITIONS[n][0], 'n': sum(r['flag_' + n] for r in results),
                'pct_all_submissions': 100 * sum(r['flag_' + n] for r in results) / len(rows)} for n in DEFINITIONS]
    write_csv(destination / 'flag_summary.csv', summary)
    item_rows = []
    for f in [f for items in PAGE_ITEMS.values() for f in items]:
        applicable = []
        for r in rows:
            required = expected_fields(r)
            if f in required or (f == 'improvement_open' and reached(r, 'text')):
                applicable.append(r)
        nmiss = sum(not r[f] for r in applicable)
        item_rows.append({'variable': f, 'applicable_n': len(applicable), 'missing_n': nmiss,
                          'missing_pct': 100 * nmiss / len(applicable) if applicable else None,
                          'nonapplicable_n': len(rows) - len(applicable),
                          'invalid_numeric_n': sum(bool(r[f]) and (number(r[f]) is None or not RANGES[f][0] <= number(r[f]) <= RANGES[f][1] or (f not in CONTINUOUS and number(r[f]) != int(number(r[f])))) for r in applicable) if f in RANGES else 0})
    write_csv(destination / 'item_quality.csv', item_rows)
    dropoff = [{'page': p, 'reached_n': sum(reached(r, p) and (p != 'customer' or number(r['current_mealkit_customer']) == 1) for r in rows),
                'breakoff_last_page_n': sum(r['last_page'] == p and r['response_status'] == 'partial' for r in rows)} for p in PAGES]
    write_csv(destination / 'page_dropoff.csv', dropoff)
    write_csv(destination / 'sample_composition.csv', composition(rows, cleaned))
    outcomes = [dict(stage=stage, **m) for stage, data in [('raw', rows), ('cleaned', cleaned)] for m in outcome_metrics(data)]
    write_csv(destination / 'outcome_comparison.csv', outcomes)
    technical = []
    for version in sorted({r['survey_version'] for r in rows}):
        subset = [a for r, a in zip(rows, results) if r['survey_version'] == version]
        for flag_name, (criterion, _) in DEFINITIONS.items():
            if criterion == 'technical':
                count = sum(a['flag_' + flag_name] for a in subset)
                technical.append({'survey_version': version, 'flag': flag_name, 'version_n': len(subset), 'flagged_n': count, 'flagged_pct': 100 * count / len(subset)})
    write_csv(destination / 'technical_by_version.csv', technical)
    sensitivity = []; sensitivity_runs = []
    alternatives = [('lenient', replace(config, speed_fraction=.25, exclude_domains=3, require_complete=False)),
                    ('selected', config), ('strict', replace(config, speed_fraction=.6, exclude_domains=2, require_complete=False)),
                    ('complete_case', replace(config, require_complete=True))]
    for label, candidate in alternatives:
        a, c = (results, cleaned) if candidate == config else audit(rows, candidate)
        sensitivity_runs.append((label, a, c))
        for m in outcome_metrics(c):
            sensitivity.append({'policy': label, 'speed_fraction': candidate.speed_fraction, 'exclude_domains': candidate.exclude_domains,
                                'require_complete': candidate.require_complete, 'retained_n': len(c),
                                'excluded_n': sum(r['decision'].startswith('exclude') for r in a),
                                'held_n': sum(r['decision'].startswith('hold') for r in a), **m})
    write_csv(destination / 'sensitivity.csv', sensitivity)
    manifest = {'generated_at_utc': datetime.now(timezone.utc).isoformat(), 'input_name': source.name,
                'input_sha256': sha256(source), 'script_sha256': sha256(__file__), 'config': asdict(config),
                'input_rows': len(rows), 'retained_rows': len(cleaned), 'decision_counts': dict(Counter(r['decision'] for r in results)),
                'answer_key_used': bool(args.answer_key), 'output_files': []}
    evaluation = None
    if args.answer_key:
        evaluation, scenarios, benchmarks = evaluate(rows, results, cleaned, args.answer_key)
        write_csv(destination / 'evaluation.csv', evaluation)
        write_csv(destination / 'evaluation_by_scenario.csv', scenarios)
        write_csv(destination / 'truth_benchmarks.csv', benchmarks)
        labelled_sensitivity = []
        for label, policy_results, policy_cleaned in sensitivity_runs:
            policy_evaluation = evaluation if label == 'selected' else evaluate(rows, policy_results, policy_cleaned, args.answer_key)[0]
            labelled_sensitivity.extend(dict(policy=label, **m) for m in policy_evaluation)
        write_csv(destination / 'sensitivity_evaluation.csv', labelled_sensitivity)
        manifest['answer_key_sha256'] = sha256(args.answer_key)
    report = ['# Survey response quality audit', '',
              f'Submissions: {len(rows)}. Retained: {len(cleaned)}. Decisions: {json.dumps(manifest["decision_counts"], sort_keys=True)}.', '',
              '## Policy', '',
              f'Speed flags use {config.speed_fraction:.2f} × the completed-session peer median, matched by customer route and device (fallback: route only). At least {config.min_peer_group} peers are required. Page checks use page/device medians. These are exercise thresholds, not universal quality standards.', '',
              f'Exclude known ineligible sessions, additional submissions sharing strong identifiers, and responses with at least {config.exclude_domains} independent behavioural domains. Domains are speed, pattern, attention, logic and text. Multiple flags within one domain count once. Unknown eligibility is held for review.', '',
              'Missing/partial responses are retained for available-item analysis unless complete-case policy is requested. Implausible or structurally unexpected fields are set missing in a separate cleaned file. Contradictory purchase fields are both set missing. Raw records are untouched. Ambiguous single-domain cases remain available with review flags.', '',
              'Potential v1.0 intent codes are set missing by default. --repair-intent-codes explicitly authorizes the simulated 10→1, …, 50→5 mapping after verification. It must not be used on a different questionnaire without checking its codebook.', '',
              'Duplicate groups retain the earliest started session, with response_id as a tie-breaker. The simulation answer key identifies its intended original independently; these policies may select different members. Detection of a duplicate group does not prove which session was the original.', '',
              '## Results', '', '| Flag | Count | % of submissions |', '|---|---:|---:|']
    report += [f'| {x["flag"]} | {x["n"]} | {x["pct_all_submissions"]:.2f} |' for x in summary if x['n']]
    report += ['', '## Interpretation', '',
               'Shared IPs, shared devices, exact repeated answers, brief text, long pauses and spending outliers are informational. Uniform ratings alone are review evidence. Text relevance uses a small, disclosed topic-vocabulary heuristic and requires manual inspection; it cannot establish whether a response is truthful, human or AI-written.', '',
               'Raw outcome summaries deliberately retain invalid numeric codes to expose their impact. Clean summaries use the retained cohort and valid available items. n_valid and n_cohort show denominators. Raw-versus-cleaned differences mix measurement changes, exclusions and missingness. No weighting or population inference is performed; Pearson correlations are descriptive and use pairwise available observations.', '',
               'Inspect sample_composition.csv for differential exclusion by age, gender, device, source and version. sensitivity.csv compares lenient, selected, strict and complete-case policies. This evaluates robustness rather than picking a policy that produces preferred substantive results.', '',
               'Potential technical faults are indicators; attribution to the survey system versus the respondent requires collection logs or codebook review. Metadata faults are not automatically classified as bad respondents.', '']
    if evaluation:
        report += ['## Optional labelled evaluation', '',
                   'The answer key was read only after the audit decisions and sensitivity outputs were computed. Metrics here are descriptive evaluation of the supplied simulation; this is not an independent holdout if you subsequently tune thresholds on these same labels.', '',
                   'evaluation.csv distinguishes broad record-quality detection from unreliable-respondent detection and whole-record exclusion. evaluation_by_scenario.csv highlights valid lookalikes. truth_benchmarks.csv separates measurement error on exactly matched respondents from total error versus the full eligible, unique simulated cohort. Truth values are never used to clean responses.', '']
    else:
        report += ['The answer key was not read. Re-run into a new output directory with --answer-key to obtain labelled evaluation.', '']
    report += ['Reproduce this run using run_manifest.json (configuration and SHA-256 hashes). Review flag definitions and record-level reasons before presenting a final exclusion policy.', '']
    (destination / 'audit_report.md').write_text('\n'.join(report), encoding='utf-8')
    manifest['output_files'] = [n for n in output_names if n == 'run_manifest.json' or (destination / n).exists()]
    (destination / 'run_manifest.json').write_text(json.dumps(manifest, indent=2, allow_nan=False) + '\n', encoding='utf-8')
    print(f'Audited {len(rows)} submissions; retained {len(cleaned)}. Results: {destination}')

def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('input', help='Path to survey_responses.csv')
    parser.add_argument('--output', default='audit_results', help='New directory for audit outputs')
    parser.add_argument('--answer-key', help='Optional answer_key.csv; not needed for the audit')
    parser.add_argument('--speed-fraction', type=float, default=.4)
    parser.add_argument('--exclude-domains', type=int, default=2)
    parser.add_argument('--min-peer-group', type=int, default=10)
    parser.add_argument('--require-complete', action='store_true', help='Exclude partials and reached required-item missingness')
    parser.add_argument('--repair-intent-codes', action='store_true', help='Use the verified simulation-specific v1.0 intent mapping')
    parser.add_argument('--overwrite', action='store_true', help='Replace previously generated audit outputs')
    args = parser.parse_args()
    try:
        run(args)
    except (ValueError, OSError, KeyError) as error:
        parser.exit(2, f'Error: {error}\n')

if __name__ == '__main__':
    main()
