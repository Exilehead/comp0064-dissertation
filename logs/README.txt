Attack 1 and 3:

How original protocal prevent this attack?
1. make_vote's safety check

Why needs detector?
1. No indication of who is doing the attack
2. No indication of what attack is performed
3. No indication of what type of attack it is (safety/liveness)

How to make malicious leader?
1. One leader proposes 2 blocks at round 10

How to detect that malicious leader?
1. CTRL-F "Satisfy SR2? false"
2. That means block there violated safety rule 2
3. get block.round is 10 above
4. from all logs, see who proposed block 10 by CTRL-F "Created B10"

How to make malicious voter?
1. rand cannot be used, use local system time to generate random number
2. Set in make_vote() to get a random number [0, 100, 200...900] by system time's ms
3. If one voter/ multiple voteres gets 500 randomly then it/they is chose to be the malicious voter

How to detect malicious voter?
1. Log all voting information "I'm voter"
2. Normal: see who vote twice with diff QC
   Optimized: also see who vote once for malicious proposal

Why not liveness?
1. second if statement in core.rs round = 10 puts QC a diff value there, thus cannot be same messages
sent multiple times for block round 10
2. Also, safety rule 2 won't be violated by liveness attack here. just ctrl-f "Satisfy SR2? false"
on all logs and if no then is liveness, if yes then is safety

Core -> Proposer:
Proposer -> Core: look at run function



Attack 2 and 4:

How original protocal prevent this attack?
1. process_block's :
// Ensure the block's round is as expected.
// This check is important: it prevents bad leaders from producing blocks
// far in the future that may cause overflow on the round number.
if block.round != self.round {	return Ok(()); }

Why needs detector?
1. No indication of who is doing the attack
2. No indication of what attack is performed
3. No indication of what type of attack it is (safety/liveness)

How to make malicious leader?
1. One leader proposes at round 30 a block with round number

How to detect malicious leader?
1. round 30 proposes a block with round number 15, and it was not leader -> safety -> needs detector
- handle_proposal's leader check will get it
2. round 30 proposes a block with round number 15, and it was leader, and different messages(qc) -> safety -> needs detector
- Ctrl-f committed B15" to find is same messages (QC) at that time, if not then SAFETY VIOLATION
3. round 50 proposes a block with round number 1, and it was leader, and same messages(qc) -> liveness-> needs detector
- Ctrl-f created B1" to find is it the leader at that time, if is then next step
- Ctrl-f committed B1" to find is same messages (QC) at that time, if yes then LIVENESS VIOLATION

FOR ABOVE IF CANNOT CTRLF THEN FALSE NEGATIVE THERE

4. round 40 proposes a block with round number 80 -> liveness-> needs detector
- Ctrl-f "Attack 2" to find is rounder numver > self.round

How to make malicious voter?
1. Random voter still, but in process_block func,

How to detect malicious voter?
1. Still in process_block func, ctrl-f "malicious voter tries to vote"
2. But need detector to further see is which situation and see is challenging safety rule or liveness rule.

false positive:

false negative:
if block 15 was not committed before, then cannot detect.

Detector:
threat model:
	Honest node: when finding attempts of attack(only can find attacks from leaders, not other nodes), directly report by logging attack
	Malicious node: try to not log anything, so can only find those malicious voters by logging all vote info

Proposal's round 15 and
