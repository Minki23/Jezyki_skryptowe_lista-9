import pytest
import datetime
from ipaddress import IPv4Address
from OOP_Python import SSHLogJournal, PasswordRejected, PasswordAccepted, Error, OtherInfo

#testowanie czy dobrze pobieramy czas z loga
class TestSSHLogEntryTime:
    def test_extract_time(self):
        journal = SSHLogJournal()
        journal.append("Dec 10 06:55:48 LabSZ sshd[24200]: Failed password for invalid user webmaster from 173.234.31.186 port 38926 ssh2")
        assert journal[0].time == datetime.datetime(2024, 12, 10, 6, 55, 48)

#ipv4 - dobry, zly i zaden
class TestSSHLogEntry:
    def test_get_ipv4_address_valid(self):
        journal = SSHLogJournal()
        journal.append("Dec 10 06:55:48 LabSZ sshd[24200]: Failed password for invalid user webmaster from 173.234.31.186 port 38926 ssh2")
        assert journal[0].get_ipv4_address() == IPv4Address("173.234.31.186")

    def test_get_ipv4_address_invalid(self):
        journal = SSHLogJournal()
        journal.append("Dec 10 06:55:48 LabSZ sshd[24200]: Failed password for invalid user webmaster from 666.777.88.213 port 38926 ssh2")
        assert journal[0].get_ipv4_address() == None

    def test_get_ipv4_address_none(self):
        journal = SSHLogJournal()
        journal.append("Dec 10 06:55:48 LabSZ sshd[24200]: invalid user webmaster [preauth]")
        assert journal[0].get_ipv4_address() == None



    

#testy metody append z dekoratorem dla wszystkich klas pochodnych
@pytest.mark.parametrize("content, expected_type", [
    ("Dec 10 06:55:48 LabSZ sshd[24200]: Failed password. for uucp from 103.207.39.212 port 51528 ssh2", PasswordRejected),
    ("Dec 10 06:55:48 LabSZ sshd[24200]: Accepted password. for valid user admin from 173.234.31.186 port 38926 ssh2", PasswordAccepted),
    ("Dec 10 06:55:48 LabSZ sshd[24200]: error: Received disconnect from 103.99.0.122: 14: No more user authentication methods available. [preauth]", Error),
    ("Dec 10 06:55:48 LabSZ sshd[24200]: kotki sa super slodkie i kochane aa", OtherInfo),
])
def test_journal_append(content, expected_type):
    journal = SSHLogJournal()
    journal.append(content)
    assert journal[0] == expected_type(content)



#tu sobie po orpstu napsialam testy zeby sprawdzic czy kazda z tych funkcji dziala - dziala

class TestPasswordRejected:
    def test_validate_true(self):
        entry = PasswordRejected("Dec 10 06:55:48 LabSZ sshd[24200]: Failed password for invalid user webmaster from 173.234.31.186 port 38926 ssh2")
        assert entry.validate() is True

    def test_validate_false(self):
        entry = PasswordRejected("Dec 10 06:55:48 LabSZ sshd[24200]: Accepted password for invalid user webmaster from 173.234.31.186 port 38926 ssh2")
        assert entry.validate() is False

class TestPasswordAccepted:
    def test_validate_true(self):
        entry = PasswordAccepted("Dec 10 06:55:48 LabSZ sshd[24200]: Accepted password for valid user admin from 173.234.31.186 port 38926 ssh2")
        assert entry.validate() is True
    def test_validate_false(self):
        entry = PasswordAccepted("Dec 10 06:55:48 LabSZ sshd[24200]: Failed password for invalid user webmaster from 173.234.31.186 port 38926 ssh2")
        assert entry.validate() is False
    
class TestError:
    def test_validate_true(self):
        entry = Error("Dec 10 06:55:48 LabSZ sshd[24200]: error occurred while processing request")
        assert entry.validate() is True
    def test_validate_false(self):
        entry = Error("Dec 10 06:55:48 LabSZ sshd[24200]: kotki sa slodziutkie")
        assert entry.validate() is False
class TestOtherInfo:
    def test_validate_true(self):
        entry = OtherInfo("Dec 10 06:55:48 LabSZ sshd[24200]: Some other info message")
        assert entry.validate() is True
