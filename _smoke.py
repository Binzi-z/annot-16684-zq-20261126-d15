from custody import Ledger
from custody.synthetic import fixed_timeline

tl = fixed_timeline()
print('arrivals', len(tl['arrivals']))
led = Ledger()
for raw in tl['arrivals']:
    led.add(raw)
a = led.current_analysis()
print('summary', a.summary())
for c in tl['claims']:
    v = a.assess(c, tl['required'][c])
    cert = v.certificate
    print(c, '->', v.status, v.reason,
          cert.seats if cert else None,
          cert.seed if cert else None,
          v.contradiction_chain)
