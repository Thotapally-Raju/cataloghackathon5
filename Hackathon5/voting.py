from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
class SecureVoting:
    def __init__(self):
        self.privateKey = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.publicKey = self.privateKey.public_key()
        self.voteData = []
    def encryptData(self, data):
        encryptedData = self.publicKey.encrypt(
            data.encode('utf-8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encryptedData
    def decryptData(self, encryptedData):
        decryptedData = self.privateKey.decrypt(
            encryptedData,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decryptedData.decode('utf-8')
    def submitVote(self, choice):
        encryptedChoice = self.encryptData(choice)
        self.voteData.append(encryptedChoice)
        print("Vote successfully submitted.")
    def countVotes(self):
        resultCount = {}
        for vote in self.voteData:
            decryptedVote = self.decryptData(vote)
            resultCount[decryptedVote] = resultCount.get(decryptedVote, 0) + 1
        return resultCount
votingSystem = SecureVoting()
votingSystem.submitVote("OptionA")
votingSystem.submitVote("OptionB")
votingSystem.submitVote("OptionA")
votingSystem.submitVote("OptionC")
votingSystem.submitVote("OptionB")
votingSystem.submitVote("OptionA")
votingSystem.submitVote("OptionC")
votingSystem.submitVote("OptionA")
votingSystem.submitVote("OptionB")
votingSystem.submitVote("OptionC")
votingSystem.submitVote("OptionA")
votingSystem.submitVote("OptionB")
finalResults = votingSystem.countVotes()
print("Final Voting Results:", finalResults)
