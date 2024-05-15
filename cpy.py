from SSH_reader import parse_log_entry, split_into_content, get_message_type, ipv4_matcher, log_dict_pattern
from ipaddress import IPv4Address
import sys
import re
from abc import ABC, abstractmethod
import re
import datetime
from typing import Iterator, Union

time_pattern = re.compile(r"(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})")

class SSHLogEntry(ABC):

    def __init__(self, content: str):
        value_dict = parse_log_entry(content)
        self.time: str = value_dict["time"]
        self.hostname: str = value_dict["user"]
        self.raw_content: str = value_dict["raw_content"]
        self.pid: str = value_dict["code"]
        self.message: str = value_dict["message"]

    def __str__(self) -> str:
        return f'Time: {self.time}, Hostname: {self.hostname}, PID: {self.pid}, IPv4: {self.get_ipv4_address()}, Message: {self.message}'

    def get_ipv4_address(self) -> Union[IPv4Address, None]:
        match = re.search(ipv4_matcher, self.raw_content)
        if match:
            ip_address = match.group()
            ip_address = '.'.join([str(int(segment)) for segment in ip_address.split('.')])
            if (int(ip_address[:3]) >= 255):
                return None
            return IPv4Address(ip_address)
        return None

    @abstractmethod
    def validate(self) -> bool:
        second_parse = split_into_content(self.raw_content)
        if second_parse["time"] != self.time:
            return False
        if second_parse["user"] != self.hostname:
            return False
        if second_parse["code"] != self.pid:
            return False
        if second_parse["message"] != self.message:
            return False
        return True

    @property
    def has_ip(self) -> bool:
        return self.get_ipv4_address() is not None

    def __repr__(self) -> str:
        return f'SSHLogEntry(time={self.time}, hostname={self.hostname}, raw_content={self.raw_content}, pid={self.pid})'

    def __eq__(self, other: object) -> bool:
        if isinstance(other, SSHLogEntry):
            return self.time == other.time and self.hostname == other.hostname and self.raw_content == other.raw_content and self.pid == other.pid
        return False

    def __lt__(self, other: object) -> bool:
        if isinstance(other, SSHLogEntry):
            return self.time < other.time
        return NotImplemented

    def __gt__(self, other: object) -> bool:
        if isinstance(other, SSHLogEntry):
            return self.time > other.time
        return NotImplemented

class PasswordRejected(SSHLogEntry):
    def __init__(self, content: str):
        super().__init__(content)
        self.message_type: str = get_message_type(self.message)

    def validate(self) -> bool:
        if re.match(r'^.*Failed password.*$', self.message) is not None:
            return True
        return False

class PasswordAccepted(SSHLogEntry):
    def __init__(self, content: str):
        super().__init__(content)
        self.message_type: str = get_message_type(self.message)

    def validate(self) -> bool:
        super().validate()
        if re.match(r'^.*Accepted password.*$', self.message) is not None:
            return True
        return False

class Error(SSHLogEntry):
    def __init__(self, content: str):
        super().__init__(content)
        self.message_type: str = get_message_type(self.message)

    def validate(self) -> bool:
        super().validate()
        if re.match(r'^.*error.*$', self.message) is not None:
            return True
        return False

class OtherInfo(SSHLogEntry):
    def __init__(self, content: str):
        super().__init__(content)
        self.info: str = self.raw_content

    def validate(self) -> bool:
        return True

class SSHLogJournal:

    def __init__(self) -> None:
        self.i: int = 0
        self.logs: dict[int, SSHLogEntry] = {}

    def __len__(self) -> int:
        return len(self.logs)

    def __iter__(self) -> Iterator:
        return iter(self.logs)

    def __contains__(self, item: object) -> bool:
        return item in self.logs

    def append(self, content: str) -> None:
        if re.match(r'^.*Failed password.*$', content) is not None:
            self.logs[self.i] = PasswordRejected(content)
        if re.match(r'^.*Accepted password.*$', content) is not None:
            self.logs[self.i] = PasswordAccepted(content)
        if re.match(r'^.*error*$', content) is not None:
            self.logs[self.i] = Error(content)
        else:
            self.logs[self.i] = OtherInfo(content)
        self.i += 1

    def get_logs_by_criteria(self, criteria) -> list[SSHLogEntry]:
        filtered_logs = []
        for log in self.logs:
            if criteria(self.logs[log]):
                filtered_logs.append(self.logs[log])
        return filtered_logs

    def __getitem__(self, parameter) -> Union[SSHLogEntry, list[SSHLogEntry], None]:
        if isinstance(parameter, slice):
            return list(self.logs.values())[parameter.start:parameter.stop:parameter.step]
        elif isinstance(parameter, int):
            return self.logs[parameter]
        elif isinstance(parameter, str):
            match = re.search(ipv4_matcher, parameter)
            if match:
                for log in self.logs:
                    if self.logs[log].get_ipv4_address() == IPv4Address(parameter):
                        return self.logs[log]
            else:
                match = re.match(time_pattern, parameter)
                if match:
                    data = match.groupdict()
                    timestamp_str = f"2024-{data['month']}-{data['day']} {data['time']}"
                    timestamp = datetime.datetime.strptime(timestamp_str, "%Y-%b-%d %H:%M:%S")
                    for log in self.logs:
                        if self.logs[log].time == timestamp:
                            return self.logs[log]
        else:
            raise TypeError("Invalid index type. Expected int or slice.")
        return None

class SSHUser:
    def __init__(self, username: str, last_login_date: str) -> None:
        self.username: str = username
        self.last_login_date: str = last_login_date

    def validate(self) -> None:
        def validate_username(username: str) -> bool:
            pattern = r'^[a-z_][a-z0-9_-]{0,31}$'
            return re.match(pattern, username) is not None

        if validate_username(self.username):
            print(f"Username {self.username} is valid.")
        else:
            print(f"Username {self.username} is invalid.")

def main() -> None:
    user1: SSHUser = SSHUser("letvuser", "2024-12-12")
    user2: SSHUser = SSHUser("ctssh", "2024-12-12")
    user3: SSHUser = SSHUser("root", "2024-12-12")
    accept: PasswordAccepted = PasswordAccepted('Dec 10 06:55:48 LabSZ sshd[24200]: Failed password for invalid user webmaster from 173.234.31.186 port 38926 ssh2')
    reject: PasswordRejected = PasswordRejected('Dec 10 06:55:48 LabSZ sshd[24200]: Failed password for invalid user webmaster from 173.234.31.186 port 38926 ssh2')

    users: list[Union[SSHUser, PasswordAccepted, PasswordRejected]] = [user1, accept, user2, reject, user3]

    for user in users:
        user.validate()

    journal: SSHLogJournal = SSHLogJournal()

    with open("SSH.log", "r") as file:
        for line in file.readlines():
            journal.append(line)
    print(journal[0])
    logs = journal.get_logs_by_criteria(lambda log: log.get_ipv4_address() == IPv4Address("212.47.254.145"))
    print(journal["212.47.254.145"])
    print(journal['Dec 10 06:55:48'])
    print(journal[0])
    print(journal[1] == journal[1])
    print(journal.logs[0] == journal.logs[1])
    print(journal.logs[0] < journal.logs[1])
    print(journal.logs[0] > journal.logs[1])
    for log in logs:
        print(log)


if __name__ == "__main__":
    main()
