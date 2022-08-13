import os
import sys
from pickletools import int4
import time

FILE_PATH = '../hotstuff/benchmark/logs/'

proposer_list = []
proof_of_attempt_of_safety_attack = []
proof_of_attempt_of_non_safety_attack = []
voter_list = []
handler_list = []
processer_list = []

LIVENESS_OR_ACCIDENT = "This node's current action is attempting liveness attack or just is caused by timeout, ignore for this project since this project just concerns safety attack"
LIVENESS_ATTACK_TWO_PT_FOUR = "This node's is attempting liveness attack 2.4 that in current round it proposes a proposal with a round number even bigger to try overflowing"
SAFETY_ATTACK_1 = "This node is performing attack 1 that proposes multiple proposals with different QCs but same round numbers"
SAFETY_ATTACK_2_2 = "This node is performing attack 2.2 that with less round number than current round number and was not the leader for that round"
SAFETY_ATTACK_2_1 = "This node is performing attack 2.1 that with less round number than current round number and was the leader for that round but proposes a different QC"
# As normal detection in writeup
SAFETY_ATTACK_3_CORRECT_VOTE_REPORT = "This node is performing attack 3.1 that it votes for proposals in attack 1, and it is reporting CORRECT voting information"
# As optimization for avoiding malicious nodes don't show vote message or show wrong vote message to cause false negative
SAFETY_ATTACK_3_NO_OR_WRONG_VOTE_REPORT = "This node is performing attack 3.2 that it votes for proposals in attack 1, and it is reporting NO OR WRONG voting information"
# Below is similar to above
SAFETY_ATTACK_4_2_CORRECT_VOTE_REPORT = "This node is performing attack 4.2.1 that it votes for proposals in attack 2.2, and it is reporting CORRECT handling information"
SAFETY_ATTACK_4_2_NO_OR_WRONG_VOTE_REPORT = "This node is performing attack 4.2.2 that it votes for proposals in attack 2.2, and it is reporting NO OR WRONG handling information"
SAFETY_ATTACK_4_1_CORRECT_VOTE_REPORT = "This node is performing attack 4.1.1 that it votes for proposals in attack 2.1, and it is reporting CORRECT processing information"
SAFETY_ATTACK_4_1_NO_OR_WRONG_VOTE_REPORT = "This node is performing attack 4.1.2 that it votes for proposals in attack 2.1, and it is reporting NO OR WRONG processing information"

committedRoundToQc = {}
livenessRoundToQc = {}
safetyOneRoundToQc = {}
safetyattackRound = set()

attack_1_reporter_to_roundqc = {}
attack_2_reporter_to_roundqc = {}
attack_liveness_reporter_to_roundqc = {}

class Node():
    def __init__(self, name:str, round_number:int, qc_round_number:int):
        self.name = name
        self.round_number = round_number
        self.qc_round_number = qc_round_number

class Proposer(Node):
    def __init__(self, name, round_number, qc_round_number):
        super().__init__(name, round_number, qc_round_number)
    
    def __eq__(self, __o: object) -> bool:
        if (isinstance(__o, Proposer)):
            return self.name == __o.name and self.round_number == __o.round_number\
                and self.qc_round_number == __o.qc_round_number
        return False

class Handler(Node):
    def __init__(self, name, round_number, qc_round_number, leader=None):
        super().__init__(name, round_number, qc_round_number)
        self.leader=leader

class Processer(Node):
    def __init__(self, name, round_number, qc_round_number, leader=None):
        super().__init__(name, round_number, qc_round_number)
        self.leader=leader

class Voter(Node):
    def __init__(self, name, round_number, qc_round_number, leader=None):
        super().__init__(name, round_number, qc_round_number)
        self.leader=leader

class MaliciousNode(Node):
    def __init__(self, name, round_number, qc_round_number, attack_id, description):
        super().__init__(name, round_number, qc_round_number)
        self.attack_id = attack_id
        self.description = description
    def __eq__(self, __o: object) -> bool:
        if (isinstance(__o, MaliciousNode)):
            return self.name == __o.name and self.round_number == __o.round_number\
                and self.qc_round_number == __o.qc_round_number and self.attack_id == __o.attack_id \
                    and self.description == __o.description
        return False

class MaliciousButDueToLivenessOrAccidentNode(Node):
    def __init__(self, name, round_number, qc_round_number, description):
        super().__init__(name, round_number, qc_round_number)
        self.description = description
    def __eq__(self, __o: object) -> bool:
        if (isinstance(__o, MaliciousButDueToLivenessOrAccidentNode)):
            return self.name == __o.name and self.round_number == __o.round_number\
                and self.qc_round_number == __o.qc_round_number and self.description == __o.description
        return False

def addProposer(new_proposer):
    proposer_list.append(new_proposer)

#https://www.tutorialspoint.com/How-to-sort-the-objects-in-a-list-in-Python#:~:text=How%20to%20sort%20the%20objects%20in%20a%20list,just%20pass%20in%20the%20reverse%20parameter%20as%20well.
def getObjKeyByRoundNumber(obj):
    return obj.round_number

def parseLog():
    node_files = [f_name for f_name in os.listdir(FILE_PATH)\
        if f_name.startswith('node')]
    # First pass loop get all proposers for creating blocks
    for file in node_files:
        with open(FILE_PATH+file) as f:
            lines = f.readlines()
            node_name = ''
            for i in range(0, len(lines)):
                
                line_list = lines[i].split(' ')
                # print(line_list)
                # Assign node name
                if len(line_list) >= 7 and line_list[6] == 'successfully':
                    node_name = line_list[5]
                    #print(node_name)
                # Record created block info, or detect liveness/accident if duplicate
                if len(line_list) >= 6 and line_list[4] == 'Created' and line_list[5] == 'with':
                    # Don't add duplicate, or add proposer and what is proposed
                    
                    if (len(proposer_list) == 0):
                        addProposer(Proposer(node_name, int(line_list[8]), int(line_list[11])))
                        #addCreateCommitInfo(node_name, int(line_list[8]), int(line_list[11]))
                    else:
                        if (Proposer(node_name, int(line_list[8]), int(line_list[11])) != proposer_list[-1]):
                            addProposer(Proposer(node_name, int(line_list[8]), int(line_list[11])))
                            #addCreateCommitInfo(node_name, int(line_list[8]), int(line_list[11]))
                        else:
                            detectLivenessOrAccident(node_name, int(line_list[8]), int(line_list[11]), LIVENESS_OR_ACCIDENT)
    # Second pass loop detect attacks or parse attacks related info to analysis further later
    for file in node_files:
        with open(FILE_PATH+file) as f:
            lines = f.readlines()
            node_name = ''
            for i in range(0, len(lines)):
                
                line_list = lines[i].split(' ')
                # print(line_list)
                # Assign node name
                if len(line_list) >= 7 and line_list[6] == 'successfully':
                    node_name = line_list[5]
                
                # Parse Committed block Info
                if len(line_list) >= 7 and line_list[4] == 'Committed' and line_list[6] == 'with':
                    committedRoundToQc[int(line_list[5][1:])] = int(line_list[8])
                
                # Detect Attack 1
                if len(line_list) >= 7 and line_list[4] == 'Attack' and line_list[5] == '1':
                    # print(lines[i+2])
                    # Sometimes there will be "created bxx" logged before safety check log

                    # Following many while is for parsing correct info that ignores those randomly timeout message inserted
                    pos = 2
                    while len(lines[i+pos].split(' ')) < 8 or (lines[i+pos].split(' ')[6] != 'Safety' and lines[i+pos].split(' ')[7] != '1'):
                        pos += 1
                    locationSRO = pos
                    while len(lines[i+pos].split(' ')) < 8 or (lines[i+pos].split(' ')[6] != 'Safety' and lines[i+pos].split(' ')[7] != '2'):
                        pos += 1
                    locationSRT = pos
                    while len(lines[i+pos].split(' ')) < 5 or lines[i+pos].split(' ')[4] != "Proposal's":
                        pos += 1
                    locationAI = pos
                    while len(lines[i+pos].split(' ')) < 5 or lines[i+pos].split(' ')[4] != "I":
                        pos += 1
                    locationReporter = pos
                    '''if lines[i+2].split(' ')[4] == "Created":
                        locationSRO += 2
                        locationSRT += 2
                        locationAI += 2
                        locationReporter += 2'''
                    checkSafetyRuleOne = lines[i+locationSRO].split(' ')[9].strip()
                    checkSafetyRuleTwo = lines[i+locationSRT].split(' ')[9].strip()
                    # Three scenarios:
                    # 1. Safety Rule 1 true and Safety Rule 2 false: Liveness
                    # 2. Safety Rule 1 false and Safety Rule 2 false: Safety Attack 1
                    # 3. Other: Liveness Or Accident
                    line_attack_info = lines[i+locationAI].split(' ')
                    if checkSafetyRuleOne == "true" and checkSafetyRuleTwo == "false":
                        detectLivenessOrAccident(line_attack_info[6].strip(), round_number=int(line_attack_info[9].strip()), \
                                qc_round_number=int(line_attack_info[17].strip()), description=LIVENESS_ATTACK_TWO_PT_FOUR)
                        attackReporter(-1, lines[i+locationReporter].split(' ')[7].strip(), int(line_attack_info[9].strip()), int(line_attack_info[17].strip()))
                    # Optimizing for improving false positive: sometimes honest nodes report but curr round - 1 = block round due to 
                    # concurrency issue that global round is updated but block is sent slower, thus consider this scenario as honest behavior 
                    elif checkSafetyRuleOne == "false" and checkSafetyRuleTwo == "false" and \
                        (int(line_attack_info[9].strip()) == int(line_attack_info[13].strip()) or int(line_attack_info[9].strip()) + 1 == int(line_attack_info[13].strip())):
                        detectSafetyAttack(line_attack_info[6].strip(), int(line_attack_info[9].strip()), int(line_attack_info[17].strip()),\
                                1, SAFETY_ATTACK_1)
                        attackReporter(1, lines[i+locationReporter].split(' ')[7].strip(), int(line_attack_info[9].strip()), int(line_attack_info[17].strip()))

                # Detect attack 2
                if len(line_list) >= 7 and line_list[4] == 'Attack' and line_list[5] == '2' \
                    and line_list[6] == 'definitely':
                    line_attack_info = lines[i+1].split(' ')
                    detectSafetyAttack(line_attack_info[6].strip(), int(line_attack_info[9].strip()), int(line_attack_info[17].strip()),\
                                2, SAFETY_ATTACK_2_2)
                    attackReporter(2, lines[i+2].split(' ')[6].strip(), int(lines[i+1].split(' ')[9]), int(lines[i+1].split(' ')[17]))
                if len(line_list) >= 7 and line_list[4] == 'Attack' and line_list[5] == '2' \
                    and line_list[6] == 'potentially':
                    
                    # IMPORTANT: round check control false positive that
                    # eg: when someone doing attack 2.1, there will be two proposers
                    # P1(round=15,leader=L1,qc_round_number=14) which is honest,
                    # And the malicious proposer, if it wants to do safety attack, it must
                    # proposes a P with qc less than 14
                    # Thus the other is P2(round=15,leader=Lmalicious, qc_round_number=0)
                    # And in previous sorting P2 is in front of P1, and will be checked while
                    # leaving P1 innocent. And if there's multiple malicious proposals Pn with
                    # same round number, all of them other than the correct one will be checked
                    # Limitation: there's edge case that if there's innocent proposal with 
                    # P1(round=15,leader=L1,qc_round_number=13) while malicious proposal with
                    # P1(round=15,leader=L1,qc_round_number=14), then cannot detect

                    # FIX BUG 2: ATTACK 2.2 NOT HADNLED BECAUSE DIDN'T SORT PROPOSER_LIST DYNAMICALLY
                    proposer_list.sort(key=lambda x: (x.round_number))
                    for proposer_index in range(0, len(proposer_list)-1):
                        #print( proposer_list[proposer_index].round_number, proposer_list[proposer_index].qc_round_number,)
                        if proposer_list[proposer_index].round_number != proposer_list[proposer_index+1].round_number:
                            continue
                        if proposer_list[proposer_index].qc_round_number == proposer_list[proposer_index+1].qc_round_number:
                            continue
                        # This is for 2.1. Rp = Rc, Lp != Lc
                        # Optimization: Above can cause false porisitve when message , thus do above if statement
                        '''if proposer_list[proposer_index].name != lines[i+2].split(' ')[6] and proposer_list[proposer_index].round_number == int(lines[i+2].split(' ')[9])\
                            :
                            #print("attack 2.1 here", lines[i+2])
                            detectSafetyAttack(lines[i+2].split(' ')[6], int(lines[i+2].split(' ')[9].strip()), int(lines[i+2].split(' ')[17].strip()),\
                                2, SAFETY_ATTACK_2_1)
                            attackReporter(2, lines[i+3].split(' ')[7].strip(), int(lines[i+2].split(' ')[9]), int(lines[i+2].split(' ')[17]))
                            continue'''
                        try:
                            if proposer_list[proposer_index].name == lines[i+2].split(' ')[6] and proposer_list[proposer_index].round_number == int(lines[i+2].split(' ')[9])\
                             and proposer_list[proposer_index].qc_round_number != int(lines[i+2].split(' ')[17]):
                                
                                detectSafetyAttack(lines[i+2].split(' ')[6], int(lines[i+2].split(' ')[9].strip()), int(lines[i+2].split(' ')[17].strip()),\
                                2, SAFETY_ATTACK_2_1)
                                attackReporter(2, lines[i+3].split(' ')[7].strip(), int(lines[i+2].split(' ')[9]), int(lines[i+2].split(' ')[17]))
                        except:
                            if proposer_list[proposer_index].name == lines[i+3].split(' ')[6] and proposer_list[proposer_index].round_number == int(lines[i+3].split(' ')[9])\
                             and proposer_list[proposer_index].qc_round_number != int(lines[i+2].split(' ')[17]):
                            #print("attack 2.2 here", lines[i+2])
                                detectSafetyAttack(lines[i+3].split(' ')[6], int(lines[i+3].split(' ')[9].strip()), int(lines[i+3].split(' ')[17].strip()),\
                                2, SAFETY_ATTACK_2_1)
                                attackReporter(2, lines[i+4].split(' ')[7].strip(), int(lines[i+4].split(' ')[9]), int(lines[i+3].split(' ')[17]))
                        
                # Record voter info to try detect malicious voters for attack 3 later
                if len(line_list) >= 6 and line_list[4] == "I'm" and line_list[5] == "voter":
                    voter_list.append(Voter(name=node_name, round_number=int(line_list[14].strip()), \
                        qc_round_number=int(line_list[17].strip()), leader=line_list[20].strip()))
                # Record handler info to try detect malicious voters for attack 4.1 later
                if len(line_list) >= 6 and line_list[4] == "I'm" and line_list[5] == "handler":
                    handler_list.append(Handler(name=node_name, round_number=int(line_list[14].strip()), \
                        qc_round_number=int(line_list[17].strip()), leader=line_list[20].strip()))
                # Record processor info to try detect malicious voters for attack 4.2 later
                if len(line_list) >= 6 and line_list[4] == "I'm" and line_list[5] == "processor":
                    processer_list.append(Processer(name=node_name, round_number=int(line_list[14].strip()), \
                        qc_round_number=int(line_list[17].strip()), leader=line_list[20].strip()))
                    

    # sort proposer by round number
    proposer_list.sort(key=lambda x: (x.name, x.round_number))
    proof_of_attempt_of_safety_attack.sort(key=getObjKeyByRoundNumber)
    proof_of_attempt_of_non_safety_attack.sort(key=getObjKeyByRoundNumber)
    
    # https://www.techiedelight.com/sort-list-of-objects-by-multiple-attributes-python/#:~:text=A%20Pythonic%20solution%20to%20in-place%20sort%20a%20list,key%20and%20reverse%20and%20produces%20a%20stable%20sort.
    voter_list.sort(key=lambda x: (x.name, x.round_number))
    handler_list.sort(key=lambda x: (x.name, x.round_number))

    # Remove duplicate 
    if len(proof_of_attempt_of_safety_attack) != 0:
        remove_duplicate_safety_attack()
    if len(proof_of_attempt_of_non_safety_attack) != 0:
        remove_duplicate_liveness_attack()
    #for proposer in proposer_list:
        #print(proposer.name, proposer.round_number, proposer.qc_round_number)
    #print(committedRoundToQc)
    

def attackReporter(attack_id, reporter, round, qc_round):
    if attack_id == 1:
        if attack_1_reporter_to_roundqc.get(reporter, "default") == "default":
            #print("iii",reporter)
            attack_1_reporter_to_roundqc[reporter] = [[round, qc_round]]
        else:
           #print("reporter",reporter)
            attack_1_reporter_to_roundqc[reporter].append([round, qc_round])
    elif attack_id == 2:
        if attack_2_reporter_to_roundqc.get(reporter, "default") == "default":
            attack_2_reporter_to_roundqc[reporter] = [[round, qc_round]]
        else:
            attack_2_reporter_to_roundqc[reporter].append([round, qc_round])
    else:
        if attack_liveness_reporter_to_roundqc.get(reporter, "default") == "default":
            attack_liveness_reporter_to_roundqc[reporter] = [[round, qc_round]]
        else:
            attack_liveness_reporter_to_roundqc[reporter].append([round, qc_round])

# Util for adding safety attack proof for one malicious node
def detectSafetyAttack(name, round_number, qc_round_number, attack_id, description):
    proof_of_attempt_of_safety_attack.append(MaliciousNode(name=name,\
                                round_number=round_number, qc_round_number=qc_round_number, \
                                    attack_id=attack_id, description=description))

# Util for removing dup
def remove_duplicate_safety_attack():
    #print("DEDUP")
    if len(proof_of_attempt_of_safety_attack) == 0:
        return
    deduplicated_proof_of_attempt_of_safety_attack = [proof_of_attempt_of_safety_attack[0]]
    for i in range(1, len(proof_of_attempt_of_safety_attack)):
        if proof_of_attempt_of_safety_attack[i] != proof_of_attempt_of_safety_attack[i-1]:
            deduplicated_proof_of_attempt_of_safety_attack.append(proof_of_attempt_of_safety_attack[i])
    proof_of_attempt_of_safety_attack.clear()
    for i in deduplicated_proof_of_attempt_of_safety_attack:
        safetyattackRound.add(i.round_number)
        proof_of_attempt_of_safety_attack.append(i)

# Util for removing dup
def remove_duplicate_liveness_attack():
    #print("DEDUP")
    if len(proof_of_attempt_of_non_safety_attack) == 0:
        return
    deduplicated_proof_of_attempt_of_non_safety_attack = [proof_of_attempt_of_non_safety_attack[0]]
    for i in range(1, len(proof_of_attempt_of_non_safety_attack)):
        if proof_of_attempt_of_non_safety_attack[i] != proof_of_attempt_of_non_safety_attack[i-1]:
            deduplicated_proof_of_attempt_of_non_safety_attack.append(proof_of_attempt_of_non_safety_attack[i])
    proof_of_attempt_of_non_safety_attack.clear()
    for i in deduplicated_proof_of_attempt_of_non_safety_attack:
        proof_of_attempt_of_non_safety_attack.append(i)

# Detect Attack 1: One leader proposes proposals with different QCs but same round numbers within 1 round
# Also detect Attack 2.1: 
# One leader proposes proposals with non-consecutive round number R
# Suppose current round number CR,
# Current leader is L
# Leader in R was PL
# If R < CR, L ! PL
# Then Attack 2.1
# Also detect Attack 2.2: 
# One leader proposes proposals with non-consecutive round number R
# Suppose current round number CR,
# Current leader is L
# Leader in R was PL
# L's proposal's QC in CR is QC
# RL's proposal was PQC
# If R < CR, L = PL, and QC != PQC
# Then Attack 2.2
    

# Just put liveness or accidental stuff inside 
def detectLivenessOrAccident(name, round_number, qc_round_number, description):
    proof_of_attempt_of_non_safety_attack.append(MaliciousButDueToLivenessOrAccidentNode(name, round_number, qc_round_number, description ))

# Detect attack 2.2
def detectAttackTwoPtTwo():
    for i in range(1,len(proposer_list)):
        # FIX BUG 3: proposer_list[i].qc_round_number != proposer_list[i-1].qc_round_number WAS 
        # NOT INCLUDED AT FIRST SO SOME LIVENESS ATTACK ARE MISINTERPRETED AS 
        if proposer_list[i].name == proposer_list[i-1].name and \
            proposer_list[i].round_number == proposer_list[i-1].round_number and \
            proposer_list[i].qc_round_number != proposer_list[i-1].qc_round_number and \
            proposer_list[i].round_number not in safetyattackRound:
            detectSafetyAttack(proposer_list[i].name, proposer_list[i].round_number, \
                proposer_list[i].qc_round_number, 2, SAFETY_ATTACK_2_1)

def initDetector():
    detectAttackTwoPtTwo()

# Detect attack 3
def detectAttackThree():
    if len(proof_of_attempt_of_safety_attack) == 0:
        return
    attack_one_list = []
    # Gather all leaders doing attack 1
    for attack in proof_of_attempt_of_safety_attack:
        if attack.attack_id == 1:
            attack_one_list.append(attack)
            #print(attack.name,attack.round_number, attack.qc_round_number, attack.description )
    
    for attack in attack_one_list:
        for voter_index in range(0, len(voter_list)):
            #print(voter_list[voter_index].name, voter_list[voter_index].round_number, voter_list[voter_index].qc_round_number, voter_list[voter_index].leader)
            
            # Find 3.1 by comparing if voter shows voting message that matches the malicious leader's behavior in Attack 1
            if voter_list[voter_index].round_number == attack.round_number and \
                voter_list[voter_index].qc_round_number == attack.qc_round_number and\
                voter_list[voter_index].leader == attack.name and\
                    proof_of_attempt_of_safety_attack[-1] != MaliciousNode(name=voter_list[voter_index].name, round_number=voter_list[voter_index].round_number,\
                    qc_round_number=voter_list[voter_index].qc_round_number, attack_id=3, description=SAFETY_ATTACK_3_CORRECT_VOTE_REPORT):
                detectSafetyAttack(name=voter_list[voter_index].name, round_number=voter_list[voter_index].round_number,\
                    qc_round_number=voter_list[voter_index].qc_round_number, attack_id=3, description=SAFETY_ATTACK_3_CORRECT_VOTE_REPORT)
                #print(voter_list[voter_index].name, voter_list[voter_index].round_number, voter_list[voter_index].qc_round_number)

            # Find 3.2 by seeing whether voter did report the malicious leader for Attack 1 by comparing with attack_1_reporter_to_roundqc
            try:
                #print(attack_1_reporter_to_roundqc)
                if voter_list[voter_index].round_number == attack.round_number and \
                    voter_list[voter_index].qc_round_number != attack.qc_round_number and\
                    voter_list[voter_index+1].round_number != attack.round_number:
                    innocent = False
                    for attacker in proof_of_attempt_of_safety_attack:
                        if attacker.description == SAFETY_ATTACK_3_CORRECT_VOTE_REPORT and voter_list[voter_index].name ==attacker.name:
                            innocent = True
                            
                            break
                    if attack_1_reporter_to_roundqc.get(voter_list[voter_index].name, "default") != "default":
                        for i in attack_1_reporter_to_roundqc[voter_list[voter_index].name]:
                            if i[0] == attack.round_number and i[1] == attack.qc_round_number:
                                innocent = True
                                break

                    if innocent == False:
                        detectSafetyAttack(name=voter_list[voter_index].name, round_number=attack.round_number,\
                        qc_round_number=attack.qc_round_number, attack_id=3, description=SAFETY_ATTACK_3_NO_OR_WRONG_VOTE_REPORT)
                        
            except:
                if attack_1_reporter_to_roundqc.get(voter_list[voter_index].name, "default") != "default":
                    for i in attack_1_reporter_to_roundqc[voter_list[voter_index].name]:
                        if i[0] == attack.round_number and i[1] == attack.qc_round_number:
                            innocent = True
                            break

                if innocent == False:
                    detectSafetyAttack(name=voter_list[voter_index].name, round_number=voter_list[voter_index].round_number,\
                    qc_round_number=voter_list[voter_index].qc_round_number, attack_id=3, description=SAFETY_ATTACK_3_NO_OR_WRONG_VOTE_REPORT)
            

# Detect attack 4
def detectAttackFour():
    attack_two_pt_one_list = []
    # Gather all leaders doing attack 2.1
    for attack in proof_of_attempt_of_safety_attack:
        if attack.description == SAFETY_ATTACK_2_2:
            attack_two_pt_one_list.append(attack)
            #print(attack.name,attack.round_number, attack.qc_round_number, attack.description )
    for attack in attack_two_pt_one_list:
        for handler_index in range(0, len(handler_list)):
            #print("attack 4", handler.name, handler.round_number, handler.qc_round_number)
            #print("mali", attack.name, attack.round_number, attack.qc_round_number)
            # need to check leader too to avoid false positive like the 1 0, 1 0 examples

            # detect attack 4.1.1
            if handler_list[handler_index].round_number == attack.round_number and \
                handler_list[handler_index].qc_round_number == attack.qc_round_number and \
                handler_list[handler_index].leader == attack.name and\
                    proof_of_attempt_of_safety_attack[-1] != MaliciousNode(name=handler_list[handler_index].name, round_number=handler_list[handler_index].round_number,\
                    qc_round_number=handler_list[handler_index].qc_round_number, attack_id=4, description=SAFETY_ATTACK_4_2_CORRECT_VOTE_REPORT):
                detectSafetyAttack(name=handler_list[handler_index].name, round_number=handler_list[handler_index].round_number,\
                    qc_round_number=handler_list[handler_index].qc_round_number, attack_id=4, description=SAFETY_ATTACK_4_2_CORRECT_VOTE_REPORT)
                
            # detect attack 4.1.2
            try:
                #print(attack_2_reporter_to_roundqc)
                #print("handler", handler_list[handler_index].name, handler_list[handler_index].round_number, handler_list[handler_index].qc_round_number)
                # if this node doesn not report the bad leader in attack 4.1
                if handler_list[handler_index].name != handler_list[handler_index+1].name\
                and handler_list[handler_index].name not in list(attack_2_reporter_to_roundqc.keys()):
                    innocent = False
                    #print("handler", handler_list[handler_index].name, handler_list[handler_index].round_number, handler_list[handler_index].qc_round_number)
                    # check if already considered doing attack 4.1.1 and skip
                    for attacker in proof_of_attempt_of_safety_attack:
                        if attacker.description == SAFETY_ATTACK_4_2_CORRECT_VOTE_REPORT and handler_list[handler_index].name ==attacker.name:
                            innocent = True
                            break
                    
                    # check if didn't report or wrongly report
                    if attack_2_reporter_to_roundqc.get(handler_list[handler_index].name, "default") != "default":
                        for i in attack_2_reporter_to_roundqc[handler_list[handler_index].name]:
                            if i[0] == attack.round_number and i[1] == attack.qc_round_number:
                                innocent = True
                                break

                    if innocent == False:
                        detectSafetyAttack(name=handler_list[handler_index].name, round_number=attack.round_number,\
                        qc_round_number=attack.qc_round_number, attack_id=4, description=SAFETY_ATTACK_4_2_NO_OR_WRONG_VOTE_REPORT)
                        
            except: # if last name in handler_list
                if handler_list[handler_index].name not in list(attack_2_reporter_to_roundqc.keys()):
                    innocent = False
                    #print("handler", handler_list[handler_index].name, attack.round_number, attack.qc_round_number)
                    # check if already considered doing attack 4.1.1and skip
                    for attacker in proof_of_attempt_of_safety_attack:
                        if attacker.description == SAFETY_ATTACK_4_2_CORRECT_VOTE_REPORT and handler_list[handler_index].name ==attacker.name:
                            innocent = True
                            
                            break
                    
                    # check if didn't report or wrongly report
                    if attack_2_reporter_to_roundqc.get(handler_list[handler_index].name, "default") != "default":
                        for i in attack_2_reporter_to_roundqc[handler_list[handler_index].name]:
                            if i[0] == attack.round_number and i[1] == attack.qc_round_number:
                                innocent = True
                                break

                    if innocent == False:
                        detectSafetyAttack(name=handler_list[handler_index].name, round_number=attack.round_number,\
                        qc_round_number=attack.qc_round_number, attack_id=4, description=SAFETY_ATTACK_4_2_NO_OR_WRONG_VOTE_REPORT)   
    attack_two_pt_two_list = []

    # Gather all leaders doing attack 2.2
    for attack in proof_of_attempt_of_safety_attack:
        if attack.description == SAFETY_ATTACK_2_2:
            attack_two_pt_two_list.append(attack)
            #print(">>>",attack.name,attack.round_number, attack.qc_round_number, attack.description )
    for attack in attack_two_pt_two_list:
        for processer_index in range(0, len(processer_list)):
            # need to check leader too to avoid false positive like the 1 0, 1 0 examples
            # detect 4.2.1


            # FIX BUG 4: forgot to include processer_list[processer_index].name not in attack_2_reporter_to_roundqc.keys()
            # to release innocent reporter
            if processer_list[processer_index].round_number == attack.round_number and \
                processer_list[processer_index].qc_round_number == attack.qc_round_number and \
                processer_list[processer_index].leader == attack.name and\
                    proof_of_attempt_of_safety_attack[-1] != MaliciousNode(name=processer_list[processer_index].name, round_number=processer_list[processer_index].round_number,\
                    qc_round_number=processer_list[processer_index].qc_round_number, attack_id=4, description=SAFETY_ATTACK_4_1_CORRECT_VOTE_REPORT) and \
                        processer_list[processer_index].name not in attack_2_reporter_to_roundqc.keys():
                detectSafetyAttack(name=processer_list[processer_index].name, round_number=processer_list[processer_index].round_number,\
                    qc_round_number=processer_list[processer_index].qc_round_number, attack_id=4, description=SAFETY_ATTACK_4_1_CORRECT_VOTE_REPORT)
                
            # detect 4.2.2
            try:
                if processer_list[processer_index].name != processer_list[processer_index+1].name\
                and processer_list[processer_index].name not in list(attack_2_reporter_to_roundqc.keys()):
                    innocent = False
                    # check if already considered doing attack 4.2.1 for this proposal and skip
                    for attacker in proof_of_attempt_of_safety_attack:
                        if attacker.description == SAFETY_ATTACK_4_1_CORRECT_VOTE_REPORT and processer_list[processer_index].name ==attacker.name:
                            innocent = True
                            break
                    
                    # check if didn't report or wrongly report
                    if attack_2_reporter_to_roundqc.get(processer_list[processer_index].name, "default") != "default":
                        for i in attack_2_reporter_to_roundqc[processer_list[processer_index].name]:
                            if i[0] == attack.round_number and i[1] == attack.qc_round_number:
                                innocent = True
                                break

                    if innocent == False:
                        detectSafetyAttack(name=processer_list[processer_index].name, round_number=attack.round_number,\
                        qc_round_number=attack.qc_round_number, attack_id=4, description=SAFETY_ATTACK_4_1_NO_OR_WRONG_VOTE_REPORT)
            except:# last node
                if processer_list[processer_index].name not in list(attack_2_reporter_to_roundqc.keys()):
                    innocent = False
                    # check if already considered doing attack 4.2.1 for this proposal and skip
                    for attacker in proof_of_attempt_of_safety_attack:
                        if attacker.description == SAFETY_ATTACK_4_1_CORRECT_VOTE_REPORT and processer_list[processer_index].name ==attacker.name:
                            innocent = True
                            break
                    
                    # check if didn't report or wrongly report
                    if attack_2_reporter_to_roundqc.get(processer_list[processer_index].name, "default") != "default":
                        for i in attack_2_reporter_to_roundqc[processer_list[processer_index].name]:
                            if i[0] == attack.round_number and i[1] == attack.qc_round_number:
                                innocent = True
                                break

                    if innocent == False:
                        detectSafetyAttack(name=processer_list[processer_index].name, round_number=attack.round_number,\
                        qc_round_number=attack.qc_round_number, attack_id=4, description=SAFETY_ATTACK_4_1_NO_OR_WRONG_VOTE_REPORT)

# FIX BUG 1: In 10_30 it will not be 100% precision because 1, Attack 1: issue: sometimes honest block will not receive block to vote, like 10_30's 14 that node 8, when the attacker is doing 
#arrack 1, the attacker sends 2 blocks. But this node 8 didn't receive the first honest block and didn't update self.last_voted_round,
#and when it sees the second malicious block, it will say pass the safety rule 1 unexpectedly, which should not passed, causing it to be
#not reporting malicious leader, thus false positive here on wronlg cathing node 8

# Fix is depends on storing all attempts of liveness attacks, and any accidental message losses behavior
# Then compare with this list of safety attacker that any attacker wrongly caught as doing safety
# attacks 3 by not reporting malicious leaders will be considered innocent on safety attack if they 
# report and misconsidered as liveness
def detectLivenessWhichIsActuallySafetyAttack():
    innocent_voter = []
    for name, roundqc in attack_liveness_reporter_to_roundqc.items():
        for attacker in proof_of_attempt_of_safety_attack:
            for little_roundqc in roundqc:
                if name == attacker.name and little_roundqc[0] == attacker.round_number and \
                    little_roundqc[1] == attacker.qc_round_number:
                    innocent_voter.append(attacker)
    temp_proof_of_attempt_of_safety_attack = []
    for attack in proof_of_attempt_of_safety_attack:
        temp_proof_of_attempt_of_safety_attack.append(attack)
    proof_of_attempt_of_safety_attack.clear()
    for attack in temp_proof_of_attempt_of_safety_attack:
        innocent = False
        for voter in innocent_voter:
            if voter.name == attack.name and voter.round_number == attack.round_number and\
            voter.qc_round_number == attack.qc_round_number:
                innocent = True
                break
        if innocent == False:
            proof_of_attempt_of_safety_attack.append(attack)

def main():
    start_time = time.time()
    parseLog()
    initDetector()
    '''for i in voter_list:
        print("voter", i.name, i.round_number, i.qc_round_number)
    for i in handler_list:
        print("handler", i.name, i.round_number, i.qc_round_number)'''
    detectAttackThree()
    detectAttackFour()
    
    proof_of_attempt_of_safety_attack.sort(key=lambda x: (x.name, x.round_number, x.qc_round_number, x.description))
    remove_duplicate_safety_attack()
    detectLivenessWhichIsActuallySafetyAttack()
    print("\n\nFinal Safety Attack")
    for i in proof_of_attempt_of_safety_attack:
        print(i.name, i.round_number, i.qc_round_number, i.description)
    
    elapsed_time = time.time() - start_time
    print("Time to detect malicious nodes: ", elapsed_time, "seconds")

if __name__=='__main__':
    main()

def run(file, fn):
    global proposer_list
    global proof_of_attempt_of_safety_attack
    global proof_of_attempt_of_non_safety_attack
    global voter_list
    global handler_list
    global processer_list
    global livenessRoundToQc
    global safetyOneRoundToQc
    global safetyattackRound
    global attack_1_reporter_to_roundqc
    global attack_2_reporter_to_roundqc
    proposer_list = []
    proof_of_attempt_of_safety_attack = []
    proof_of_attempt_of_non_safety_attack = []
    voter_list = []
    handler_list = []
    processer_list = []
    livenessRoundToQc = {}
    safetyOneRoundToQc = {}
    safetyattackRound = set()
    attack_1_reporter_to_roundqc = {}
    attack_2_reporter_to_roundqc = {}
    temp = sys.stdout
    global FILE_PATH
    FILE_PATH = file
    print(FILE_PATH)
    f = open('tests/test' + str(fn) + '.txt','w')
    sys.stdout = f 
    start_time = time.time()
    parseLog()
    initDetector()
    detectAttackThree()
    detectAttackFour()
    proof_of_attempt_of_safety_attack.sort(key=lambda x: (x.name, x.round_number, x.qc_round_number, x.description))
    remove_duplicate_safety_attack()
    detectLivenessWhichIsActuallySafetyAttack()
    print("Final Safety Attack")
    for i in proof_of_attempt_of_safety_attack:
        print(i.attack_id, i.name, i.round_number, i.qc_round_number, i.description)
    
    elapsed_time = time.time() - start_time
    print("Time to detect malicious nodes: ", elapsed_time, "seconds")
    sys.stdout.flush()
    sys.stdout = temp
    f.close()