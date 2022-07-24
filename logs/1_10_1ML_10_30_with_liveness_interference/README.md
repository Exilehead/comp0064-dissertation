1 dead node, 10 in total

Attacks 1, 2.1, 3 and 4 are concerned

One malicious leader for attack 1
One malicious leader for attack 2.1

mode 1 is in attack 3 and 4 malicious voters will log honest messages of what it voted
as honest nodes did
mode 2 is in attack 3 and 4 malicious voters will not log any messages of what it voted
mode 3 is in attack 3 and 4 malicious voters will log wrong message of what it voted,
The detector only concern the situation that it log the exactly same voting messages with duplicate
round number and QC with committed proposal. Situation that malicious voters make a new votes messages with QC randomly chosen is not concerned since it is malformed and only cause liveness attack.

1-10 is mode 1
11-15 is mode 2
16-20 is mode 3