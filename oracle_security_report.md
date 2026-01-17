
# Oracle/Price Integrity Security Assessment Report

## Summary
This report details vulnerabilities in the `ScribeOptimistic.sol` contract related to oracle and price integrity.

## Findings

### reentrancy-events

#### opChallenge

- **Type**: function
- **File**: ../../thelist/2chronicle/scribe-v2/src/ScribeOptimistic.sol
- **Lines**: [213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255, 256, 257, 258, 259, 260, 261, 262, 263, 264, 265, 266, 267, 268, 269, 270, 271, 272, 273, 274, 275, 276, 277, 278, 279, 280, 281, 282, 283, 284, 285, 286, 287]
- **Description**: Reentrancy in ScribeOptimistic.opChallenge(IScribe.SchnorrData) (src/ScribeOptimistic.sol#213-287):
	External calls:
	- _sendETH(address(msg.sender),reward) (src/ScribeOptimistic.sol#278)
		- (ok,None) = to.call{value: amount}() (src/ScribeOptimistic.sol#586)
	Event emitted after the call(s):
	- OpChallengeRewardPaid(msg.sender,schnorrData,reward) (src/ScribeOptimistic.sol#279)
	- OpPokeChallengedSuccessfully(msg.sender,schnorrData,err) (src/ScribeOptimistic.sol#282)


#### _sendETH(address(msg.sender),reward)

- **Type**: node
- **File**: ../../thelist/2chronicle/scribe-v2/src/ScribeOptimistic.sol
- **Lines**: [278]
- **Description**: Reentrancy in ScribeOptimistic.opChallenge(IScribe.SchnorrData) (src/ScribeOptimistic.sol#213-287):
	External calls:
	- _sendETH(address(msg.sender),reward) (src/ScribeOptimistic.sol#278)
		- (ok,None) = to.call{value: amount}() (src/ScribeOptimistic.sol#586)
	Event emitted after the call(s):
	- OpChallengeRewardPaid(msg.sender,schnorrData,reward) (src/ScribeOptimistic.sol#279)
	- OpPokeChallengedSuccessfully(msg.sender,schnorrData,err) (src/ScribeOptimistic.sol#282)


#### (ok,None) = to.call{value: amount}()

- **Type**: node
- **File**: ../../thelist/2chronicle/scribe-v2/src/ScribeOptimistic.sol
- **Lines**: [586]
- **Description**: Reentrancy in ScribeOptimistic.opChallenge(IScribe.SchnorrData) (src/ScribeOptimistic.sol#213-287):
	External calls:
	- _sendETH(address(msg.sender),reward) (src/ScribeOptimistic.sol#278)
		- (ok,None) = to.call{value: amount}() (src/ScribeOptimistic.sol#586)
	Event emitted after the call(s):
	- OpChallengeRewardPaid(msg.sender,schnorrData,reward) (src/ScribeOptimistic.sol#279)
	- OpPokeChallengedSuccessfully(msg.sender,schnorrData,err) (src/ScribeOptimistic.sol#282)


#### OpChallengeRewardPaid(msg.sender,schnorrData,reward)

- **Type**: node
- **File**: ../../thelist/2chronicle/scribe-v2/src/ScribeOptimistic.sol
- **Lines**: [279]
- **Description**: Reentrancy in ScribeOptimistic.opChallenge(IScribe.SchnorrData) (src/ScribeOptimistic.sol#213-287):
	External calls:
	- _sendETH(address(msg.sender),reward) (src/ScribeOptimistic.sol#278)
		- (ok,None) = to.call{value: amount}() (src/ScribeOptimistic.sol#586)
	Event emitted after the call(s):
	- OpChallengeRewardPaid(msg.sender,schnorrData,reward) (src/ScribeOptimistic.sol#279)
	- OpPokeChallengedSuccessfully(msg.sender,schnorrData,err) (src/ScribeOptimistic.sol#282)


#### OpPokeChallengedSuccessfully(msg.sender,schnorrData,err)

- **Type**: node
- **File**: ../../thelist/2chronicle/scribe-v2/src/ScribeOptimistic.sol
- **Lines**: [282]
- **Description**: Reentrancy in ScribeOptimistic.opChallenge(IScribe.SchnorrData) (src/ScribeOptimistic.sol#213-287):
	External calls:
	- _sendETH(address(msg.sender),reward) (src/ScribeOptimistic.sol#278)
		- (ok,None) = to.call{value: amount}() (src/ScribeOptimistic.sol#586)
	Event emitted after the call(s):
	- OpChallengeRewardPaid(msg.sender,schnorrData,reward) (src/ScribeOptimistic.sol#279)
	- OpPokeChallengedSuccessfully(msg.sender,schnorrData,err) (src/ScribeOptimistic.sol#282)


### timestamp

#### _afterAuthedAction

- **Type**: function
- **File**: ../../thelist/2chronicle/scribe-v2/src/ScribeOptimistic.sol
- **Lines**: [508, 509, 510, 511, 512, 513, 514, 515, 516, 517, 518, 519, 520, 521, 522, 523, 524, 525, 526, 527, 528, 529, 530, 531, 532, 533, 534, 535, 536, 537, 538, 539, 540, 541, 542, 543, 544, 545, 546, 547, 548, 549, 550, 551, 552, 553, 554, 555, 556, 557, 558]
- **Description**: ScribeOptimistic._afterAuthedAction() (src/ScribeOptimistic.sol#508-558) uses timestamp for comparisons
	Dangerous comparisons:
	- opPokeDataFinalized = opPokeData.age + opChallengePeriod <= uint32(block.timestamp) (src/ScribeOptimistic.sol#520-521)
	- opPokeDataFinalized && opPokeData.age > _pokeData.age (src/ScribeOptimistic.sol#535)


#### opPokeDataFinalized = opPokeData.age + opChallengePeriod <= uint32(block.timestamp)

- **Type**: node
- **File**: ../../thelist/2chronicle/scribe-v2/src/ScribeOptimistic.sol
- **Lines**: [520, 521]
- **Description**: ScribeOptimistic._afterAuthedAction() (src/ScribeOptimistic.sol#508-558) uses timestamp for comparisons
	Dangerous comparisons:
	- opPokeDataFinalized = opPokeData.age + opChallengePeriod <= uint32(block.timestamp) (src/ScribeOptimistic.sol#520-521)
	- opPokeDataFinalized && opPokeData.age > _pokeData.age (src/ScribeOptimistic.sol#535)


#### opPokeDataFinalized && opPokeData.age > _pokeData.age

- **Type**: node
- **File**: ../../thelist/2chronicle/scribe-v2/src/ScribeOptimistic.sol
- **Lines**: [535]
- **Description**: ScribeOptimistic._afterAuthedAction() (src/ScribeOptimistic.sol#508-558) uses timestamp for comparisons
	Dangerous comparisons:
	- opPokeDataFinalized = opPokeData.age + opChallengePeriod <= uint32(block.timestamp) (src/ScribeOptimistic.sol#520-521)
	- opPokeDataFinalized && opPokeData.age > _pokeData.age (src/ScribeOptimistic.sol#535)


#### _currentPokeData

- **Type**: function
- **File**: ../../thelist/2chronicle/scribe-v2/src/ScribeOptimistic.sol
- **Lines**: [447, 448, 449, 450, 451, 452, 453, 454, 455, 456, 457, 458, 459, 460, 461, 462]
- **Description**: ScribeOptimistic._currentPokeData() (src/ScribeOptimistic.sol#447-462) uses timestamp for comparisons
	Dangerous comparisons:
	- opPokeDataFinalized = opPokeData.age + opChallengePeriod <= uint32(block.timestamp) (src/ScribeOptimistic.sol#453-454)
	- opPokeDataFinalized && opPokeData.age > pokeData.age (src/ScribeOptimistic.sol#457)


#### opPokeDataFinalized = opPokeData.age + opChallengePeriod <= uint32(block.timestamp)

- **Type**: node
- **File**: ../../thelist/2chronicle/scribe-v2/src/ScribeOptimistic.sol
- **Lines**: [453, 454]
- **Description**: ScribeOptimistic._currentPokeData() (src/ScribeOptimistic.sol#447-462) uses timestamp for comparisons
	Dangerous comparisons:
	- opPokeDataFinalized = opPokeData.age + opChallengePeriod <= uint32(block.timestamp) (src/ScribeOptimistic.sol#453-454)
	- opPokeDataFinalized && opPokeData.age > pokeData.age (src/ScribeOptimistic.sol#457)


#### opPokeDataFinalized && opPokeData.age > pokeData.age

- **Type**: node
- **File**: ../../thelist/2chronicle/scribe-v2/src/ScribeOptimistic.sol
- **Lines**: [457]
- **Description**: ScribeOptimistic._currentPokeData() (src/ScribeOptimistic.sol#447-462) uses timestamp for comparisons
	Dangerous comparisons:
	- opPokeDataFinalized = opPokeData.age + opChallengePeriod <= uint32(block.timestamp) (src/ScribeOptimistic.sol#453-454)
	- opPokeDataFinalized && opPokeData.age > pokeData.age (src/ScribeOptimistic.sol#457)


#### peek

- **Type**: function
- **File**: ../../thelist/2chronicle/scribe-v2/src/ScribeOptimistic.sol
- **Lines**: [382, 383, 384, 385, 386, 387, 388, 389, 390, 391]
- **Description**: ScribeOptimistic.peek() (src/ScribeOptimistic.sol#382-391) uses timestamp for comparisons
	Dangerous comparisons:
	- (val,val != 0) (src/ScribeOptimistic.sol#390)


#### (val,val != 0)

- **Type**: node
- **File**: ../../thelist/2chronicle/scribe-v2/src/ScribeOptimistic.sol
- **Lines**: [390]
- **Description**: ScribeOptimistic.peek() (src/ScribeOptimistic.sol#382-391) uses timestamp for comparisons
	Dangerous comparisons:
	- (val,val != 0) (src/ScribeOptimistic.sol#390)


#### read

- **Type**: function
- **File**: ../../thelist/2chronicle/scribe-v2/src/ScribeOptimistic.sol
- **Lines**: [324, 325, 326, 327, 328, 329, 330, 331, 332, 333, 334]
- **Description**: ScribeOptimistic.read() (src/ScribeOptimistic.sol#324-334) uses timestamp for comparisons
	Dangerous comparisons:
	- require(bool)(val != 0) (src/ScribeOptimistic.sol#332)


#### require(bool)(val != 0)

- **Type**: node
- **File**: ../../thelist/2chronicle/scribe-v2/src/ScribeOptimistic.sol
- **Lines**: [332]
- **Description**: ScribeOptimistic.read() (src/ScribeOptimistic.sol#324-334) uses timestamp for comparisons
	Dangerous comparisons:
	- require(bool)(val != 0) (src/ScribeOptimistic.sol#332)


#### _poke

- **Type**: function
- **File**: ../../thelist/2chronicle/scribe-v2/src/ScribeOptimistic.sol
- **Lines**: [67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100]
- **Description**: ScribeOptimistic._poke(IScribe.PokeData,IScribe.SchnorrData) (src/ScribeOptimistic.sol#67-100) uses timestamp for comparisons
	Dangerous comparisons:
	- pokeData.age <= age (src/ScribeOptimistic.sol#75)
	- pokeData.age > uint32(block.timestamp) (src/ScribeOptimistic.sol#79)


#### pokeData.age <= age

- **Type**: node
- **File**: ../../thelist/2chronicle/scribe-v2/src/ScribeOptimistic.sol
- **Lines**: [75]
- **Description**: ScribeOptimistic._poke(IScribe.PokeData,IScribe.SchnorrData) (src/ScribeOptimistic.sol#67-100) uses timestamp for comparisons
	Dangerous comparisons:
	- pokeData.age <= age (src/ScribeOptimistic.sol#75)
	- pokeData.age > uint32(block.timestamp) (src/ScribeOptimistic.sol#79)


#### pokeData.age > uint32(block.timestamp)

- **Type**: node
- **File**: ../../thelist/2chronicle/scribe-v2/src/ScribeOptimistic.sol
- **Lines**: [79]
- **Description**: ScribeOptimistic._poke(IScribe.PokeData,IScribe.SchnorrData) (src/ScribeOptimistic.sol#67-100) uses timestamp for comparisons
	Dangerous comparisons:
	- pokeData.age <= age (src/ScribeOptimistic.sol#75)
	- pokeData.age > uint32(block.timestamp) (src/ScribeOptimistic.sol#79)


#### tryReadWithAge

- **Type**: function
- **File**: ../../thelist/2chronicle/scribe-v2/src/ScribeOptimistic.sol
- **Lines**: [365, 366, 367, 368, 369, 370, 371, 372, 373, 374, 375, 376]
- **Description**: ScribeOptimistic.tryReadWithAge() (src/ScribeOptimistic.sol#365-376) uses timestamp for comparisons
	Dangerous comparisons:
	- pokeData.val != 0 (src/ScribeOptimistic.sol#373-375)


#### pokeData.val != 0

- **Type**: node
- **File**: ../../thelist/2chronicle/scribe-v2/src/ScribeOptimistic.sol
- **Lines**: [373, 374, 375]
- **Description**: ScribeOptimistic.tryReadWithAge() (src/ScribeOptimistic.sol#365-376) uses timestamp for comparisons
	Dangerous comparisons:
	- pokeData.val != 0 (src/ScribeOptimistic.sol#373-375)


#### peep

- **Type**: function
- **File**: ../../thelist/2chronicle/scribe-v2/src/ScribeOptimistic.sol
- **Lines**: [395, 396, 397, 398, 399, 400, 401, 402, 403, 404]
- **Description**: ScribeOptimistic.peep() (src/ScribeOptimistic.sol#395-404) uses timestamp for comparisons
	Dangerous comparisons:
	- (val,val != 0) (src/ScribeOptimistic.sol#403)


#### (val,val != 0)

- **Type**: node
- **File**: ../../thelist/2chronicle/scribe-v2/src/ScribeOptimistic.sol
- **Lines**: [403]
- **Description**: ScribeOptimistic.peep() (src/ScribeOptimistic.sol#395-404) uses timestamp for comparisons
	Dangerous comparisons:
	- (val,val != 0) (src/ScribeOptimistic.sol#403)


#### tryRead

- **Type**: function
- **File**: ../../thelist/2chronicle/scribe-v2/src/ScribeOptimistic.sol
- **Lines**: [338, 339, 340, 341, 342, 343, 344, 345, 346, 347]
- **Description**: ScribeOptimistic.tryRead() (src/ScribeOptimistic.sol#338-347) uses timestamp for comparisons
	Dangerous comparisons:
	- (val != 0,val) (src/ScribeOptimistic.sol#346)


#### (val != 0,val)

- **Type**: node
- **File**: ../../thelist/2chronicle/scribe-v2/src/ScribeOptimistic.sol
- **Lines**: [346]
- **Description**: ScribeOptimistic.tryRead() (src/ScribeOptimistic.sol#338-347) uses timestamp for comparisons
	Dangerous comparisons:
	- (val != 0,val) (src/ScribeOptimistic.sol#346)


#### opChallenge

- **Type**: function
- **File**: ../../thelist/2chronicle/scribe-v2/src/ScribeOptimistic.sol
- **Lines**: [213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255, 256, 257, 258, 259, 260, 261, 262, 263, 264, 265, 266, 267, 268, 269, 270, 271, 272, 273, 274, 275, 276, 277, 278, 279, 280, 281, 282, 283, 284, 285, 286, 287]
- **Description**: ScribeOptimistic.opChallenge(IScribe.SchnorrData) (src/ScribeOptimistic.sol#213-287) uses timestamp for comparisons
	Dangerous comparisons:
	- opPokeDataChallengeable = opPokeData.age + opChallengePeriod > uint32(block.timestamp) (src/ScribeOptimistic.sol#221-222)
	- opPokeDataStale = opPokeData.age <= _pokeData.age (src/ScribeOptimistic.sol#259)


#### opPokeDataChallengeable = opPokeData.age + opChallengePeriod > uint32(block.timestamp)

- **Type**: node
- **File**: ../../thelist/2chronicle/scribe-v2/src/ScribeOptimistic.sol
- **Lines**: [221, 222]
- **Description**: ScribeOptimistic.opChallenge(IScribe.SchnorrData) (src/ScribeOptimistic.sol#213-287) uses timestamp for comparisons
	Dangerous comparisons:
	- opPokeDataChallengeable = opPokeData.age + opChallengePeriod > uint32(block.timestamp) (src/ScribeOptimistic.sol#221-222)
	- opPokeDataStale = opPokeData.age <= _pokeData.age (src/ScribeOptimistic.sol#259)


#### opPokeDataStale = opPokeData.age <= _pokeData.age

- **Type**: node
- **File**: ../../thelist/2chronicle/scribe-v2/src/ScribeOptimistic.sol
- **Lines**: [259]
- **Description**: ScribeOptimistic.opChallenge(IScribe.SchnorrData) (src/ScribeOptimistic.sol#213-287) uses timestamp for comparisons
	Dangerous comparisons:
	- opPokeDataChallengeable = opPokeData.age + opChallengePeriod > uint32(block.timestamp) (src/ScribeOptimistic.sol#221-222)
	- opPokeDataStale = opPokeData.age <= _pokeData.age (src/ScribeOptimistic.sol#259)


#### _poke

- **Type**: function
- **File**: ../../thelist/2chronicle/scribe-v2/src/Scribe.sol
- **Lines**: [89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119]
- **Description**: Scribe._poke(IScribe.PokeData,IScribe.SchnorrData) (src/Scribe.sol#89-119) uses timestamp for comparisons
	Dangerous comparisons:
	- pokeData.age <= _pokeData.age (src/Scribe.sol#94)
	- pokeData.age > uint32(block.timestamp) (src/Scribe.sol#98)


#### pokeData.age <= _pokeData.age

- **Type**: node
- **File**: ../../thelist/2chronicle/scribe-v2/src/Scribe.sol
- **Lines**: [94]
- **Description**: Scribe._poke(IScribe.PokeData,IScribe.SchnorrData) (src/Scribe.sol#89-119) uses timestamp for comparisons
	Dangerous comparisons:
	- pokeData.age <= _pokeData.age (src/Scribe.sol#94)
	- pokeData.age > uint32(block.timestamp) (src/Scribe.sol#98)


#### pokeData.age > uint32(block.timestamp)

- **Type**: node
- **File**: ../../thelist/2chronicle/scribe-v2/src/Scribe.sol
- **Lines**: [98]
- **Description**: Scribe._poke(IScribe.PokeData,IScribe.SchnorrData) (src/Scribe.sol#89-119) uses timestamp for comparisons
	Dangerous comparisons:
	- pokeData.age <= _pokeData.age (src/Scribe.sol#94)
	- pokeData.age > uint32(block.timestamp) (src/Scribe.sol#98)


#### readWithAge

- **Type**: function
- **File**: ../../thelist/2chronicle/scribe-v2/src/ScribeOptimistic.sol
- **Lines**: [351, 352, 353, 354, 355, 356, 357, 358, 359, 360, 361]
- **Description**: ScribeOptimistic.readWithAge() (src/ScribeOptimistic.sol#351-361) uses timestamp for comparisons
	Dangerous comparisons:
	- require(bool)(pokeData.val != 0) (src/ScribeOptimistic.sol#359)


#### require(bool)(pokeData.val != 0)

- **Type**: node
- **File**: ../../thelist/2chronicle/scribe-v2/src/ScribeOptimistic.sol
- **Lines**: [359]
- **Description**: ScribeOptimistic.readWithAge() (src/ScribeOptimistic.sol#351-361) uses timestamp for comparisons
	Dangerous comparisons:
	- require(bool)(pokeData.val != 0) (src/ScribeOptimistic.sol#359)


#### _opPoke

- **Type**: function
- **File**: ../../thelist/2chronicle/scribe-v2/src/ScribeOptimistic.sol
- **Lines**: [124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210]
- **Description**: ScribeOptimistic._opPoke(IScribe.PokeData,IScribe.SchnorrData,IScribe.ECDSAData) (src/ScribeOptimistic.sol#124-210) uses timestamp for comparisons
	Dangerous comparisons:
	- opPokeDataFinalized = opPokeData.age + opChallengePeriod <= uint32(block.timestamp) (src/ScribeOptimistic.sol#142-143)
	- pokeData.age <= age (src/ScribeOptimistic.sol#155)
	- pokeData.age > uint32(block.timestamp) (src/ScribeOptimistic.sol#159)
	- opPokeData.age == age (src/ScribeOptimistic.sol#198)
	- opPokeData.age > _pokeData.age (src/ScribeOptimistic.sol#151-152)


#### opPokeDataFinalized = opPokeData.age + opChallengePeriod <= uint32(block.timestamp)

- **Type**: node
- **File**: ../../thelist/2chronicle/scribe-v2/src/ScribeOptimistic.sol
- **Lines**: [142, 143]
- **Description**: ScribeOptimistic._opPoke(IScribe.PokeData,IScribe.SchnorrData,IScribe.ECDSAData) (src/ScribeOptimistic.sol#124-210) uses timestamp for comparisons
	Dangerous comparisons:
	- opPokeDataFinalized = opPokeData.age + opChallengePeriod <= uint32(block.timestamp) (src/ScribeOptimistic.sol#142-143)
	- pokeData.age <= age (src/ScribeOptimistic.sol#155)
	- pokeData.age > uint32(block.timestamp) (src/ScribeOptimistic.sol#159)
	- opPokeData.age == age (src/ScribeOptimistic.sol#198)
	- opPokeData.age > _pokeData.age (src/ScribeOptimistic.sol#151-152)


#### pokeData.age <= age

- **Type**: node
- **File**: ../../thelist/2chronicle/scribe-v2/src/ScribeOptimistic.sol
- **Lines**: [155]
- **Description**: ScribeOptimistic._opPoke(IScribe.PokeData,IScribe.SchnorrData,IScribe.ECDSAData) (src/ScribeOptimistic.sol#124-210) uses timestamp for comparisons
	Dangerous comparisons:
	- opPokeDataFinalized = opPokeData.age + opChallengePeriod <= uint32(block.timestamp) (src/ScribeOptimistic.sol#142-143)
	- pokeData.age <= age (src/ScribeOptimistic.sol#155)
	- pokeData.age > uint32(block.timestamp) (src/ScribeOptimistic.sol#159)
	- opPokeData.age == age (src/ScribeOptimistic.sol#198)
	- opPokeData.age > _pokeData.age (src/ScribeOptimistic.sol#151-152)


#### pokeData.age > uint32(block.timestamp)

- **Type**: node
- **File**: ../../thelist/2chronicle/scribe-v2/src/ScribeOptimistic.sol
- **Lines**: [159]
- **Description**: ScribeOptimistic._opPoke(IScribe.PokeData,IScribe.SchnorrData,IScribe.ECDSAData) (src/ScribeOptimistic.sol#124-210) uses timestamp for comparisons
	Dangerous comparisons:
	- opPokeDataFinalized = opPokeData.age + opChallengePeriod <= uint32(block.timestamp) (src/ScribeOptimistic.sol#142-143)
	- pokeData.age <= age (src/ScribeOptimistic.sol#155)
	- pokeData.age > uint32(block.timestamp) (src/ScribeOptimistic.sol#159)
	- opPokeData.age == age (src/ScribeOptimistic.sol#198)
	- opPokeData.age > _pokeData.age (src/ScribeOptimistic.sol#151-152)


#### opPokeData.age == age

- **Type**: node
- **File**: ../../thelist/2chronicle/scribe-v2/src/ScribeOptimistic.sol
- **Lines**: [198]
- **Description**: ScribeOptimistic._opPoke(IScribe.PokeData,IScribe.SchnorrData,IScribe.ECDSAData) (src/ScribeOptimistic.sol#124-210) uses timestamp for comparisons
	Dangerous comparisons:
	- opPokeDataFinalized = opPokeData.age + opChallengePeriod <= uint32(block.timestamp) (src/ScribeOptimistic.sol#142-143)
	- pokeData.age <= age (src/ScribeOptimistic.sol#155)
	- pokeData.age > uint32(block.timestamp) (src/ScribeOptimistic.sol#159)
	- opPokeData.age == age (src/ScribeOptimistic.sol#198)
	- opPokeData.age > _pokeData.age (src/ScribeOptimistic.sol#151-152)


#### opPokeData.age > _pokeData.age

- **Type**: node
- **File**: ../../thelist/2chronicle/scribe-v2/src/ScribeOptimistic.sol
- **Lines**: [151, 152]
- **Description**: ScribeOptimistic._opPoke(IScribe.PokeData,IScribe.SchnorrData,IScribe.ECDSAData) (src/ScribeOptimistic.sol#124-210) uses timestamp for comparisons
	Dangerous comparisons:
	- opPokeDataFinalized = opPokeData.age + opChallengePeriod <= uint32(block.timestamp) (src/ScribeOptimistic.sol#142-143)
	- pokeData.age <= age (src/ScribeOptimistic.sol#155)
	- pokeData.age > uint32(block.timestamp) (src/ScribeOptimistic.sol#159)
	- opPokeData.age == age (src/ScribeOptimistic.sol#198)
	- opPokeData.age > _pokeData.age (src/ScribeOptimistic.sol#151-152)



## Recommendations

### Reentrancy Vulnerabilities
1. Use the Checks-Effects-Interactions pattern to ensure state changes occur before external calls.
2. Use reentrancy guards or mutexes to prevent reentrant calls.
3. Consider using OpenZeppelin's `ReentrancyGuard` contract.

### Timestamp Dependence
1. Avoid using `block.timestamp` for critical logic. Instead, use a trusted oracle for time.
2. If `block.timestamp` must be used, ensure it is not the sole determinant for critical decisions.
3. Use a time buffer to account for potential timestamp manipulation.

### Staleness Checks
1. Implement additional checks to ensure data freshness, such as requiring multiple confirmations.
2. Use a trusted time source for staleness checks.
3. Consider implementing a heartbeat mechanism to ensure regular updates.

## Conclusion
The `ScribeOptimistic.sol` contract contains several vulnerabilities related to oracle and price integrity. Addressing these vulnerabilities is critical to ensure the security and reliability of the oracle mechanism.

## Next Steps
1. Prioritize fixes based on the severity and impact of the vulnerabilities.
2. Implement the recommended changes and conduct thorough testing.
3. Perform a follow-up security assessment to ensure all vulnerabilities have been addressed.
