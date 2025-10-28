import errno
import socket
import sys
import threading
import time
import json #sterlizing packets 

# just constants 
LOCAL_DNS_ADDR = ("127.0.0.1", 21000)
QUERY_FLAG = "0000"
RESP_FLAG = "0001"
NOT_FOUND = "Record not found"



def serialize(obj: dict) -> str:
    return json.dumps(obj) #changing dict to string 

def deserialize(s: str) -> dict:
    return json.loads(s) #changing str to dict 




def handle_request(udp: "UDPConnection", rr: "RRTable", hostname: str, qtype_name: str):
    # 1 check cache 
    hit = rr.get_record(hostname, qtype_name)
    if hit:
        rr.display_table()
        return

    # 2 build DNS query JSON
    tx_id = int(time.time() * 1000) & 0xFFFFFFFF  # simple unique-ish id
    packet = {
        "id": tx_id,
        "flag": QUERY_FLAG,
        "question": {"name": hostname, "type": qtype_name},
    }

    # 3 send to Local DNS to check there 
    udp.send_message(serialize(packet), LOCAL_DNS_ADDR)

    # 4 receive response
    try:
        data, _addr = udp.receive_message()
    except KeyboardInterrupt:
        raise
    except Exception:
        print("No response from Local DNS (timeout or socket error)")
        return

    resp = deserialize(data)
    if not isinstance(resp, dict) or resp.get("id") != tx_id or resp.get("flag") != RESP_FLAG:
        print("mismatched response; ignoring.")
        return

    ans = resp.get("answer", {})
    result = ans.get("result", NOT_FOUND)
    if result != NOT_FOUND:
        ttl = int(ans.get("ttl", 60))
        rr.add_record(ans.get("name", hostname), ans.get("type", qtype_name), result, ttl, static=0)

    # 5 print after a response
    rr.display_table()


def main():
    #  Create your DNS table (cache) and UDP connection
    rr = RRTable()                         # stores cached records
    udp = UDPConnection(timeout=5)

    try:
        while True:
            #  Get user input
            input_value = input("Enter the hostname (or 'quit' to exit) ").strip()
            if input_value.lower() == "quit":
                break

            # Allow optional type: "shop.amazon.com A"
            parts = input_value.split()
            if len(parts) == 1:
                hostname, qtype_name = parts[0], "A"
            elif len(parts) == 2:
                hostname, qtype_name = parts[0], parts[1].upper()
            else:
                print("enter: <hostname> <type>")
                continue

            # Verify the type is valid
            if DNSTypes.get_type_code(qtype_name) is None:
                print("Type must be one of: A, AAAA, CNAME, NS")
                continue

            # Actually make the query
            handle_request(udp, rr, hostname, qtype_name)

    except KeyboardInterrupt:
        print("Keyboard interrupt, exiting...")
    finally:
        #  closing the socket when done
        udp.close()




class RRTable:
    def __init__(self):
        self.records = []  # list of dicts
        self.record_number = 0

        # Start the background thread
        self.lock = threading.Lock()
        self.thread = threading.Thread(target=self.__decrement_ttl, daemon=True)
        self.thread.start()

    def add_record(self, name: str, rtype: str, result: str, ttl: int, static: int = 0):
        with self.lock:
            self.records.append({
                "record_number": self.record_number,
                "name": name,
                "type": rtype,
                "result": result,
                "ttl": ttl if static == 0 else None,  # client uses dynamic; None reserved for static shape
                "static": static
            })
            self.record_number += 1

    def get_record(self, name: str, rtype: str):
        with self.lock:
            for rec in self.records:
                if rec["name"] == name and rec["type"] == rtype:
                    if rec["static"] == 1 or (rec["ttl"] is not None and rec["ttl"] > 0):
                        return rec
        return None

    def display_table(self):
        with self.lock:
            print("record_no,name,type,result,ttl,static")
            for rec in self.records:
                ttl_str = "None" if rec["ttl"] is None else str(rec["ttl"])
                print(f'{rec["record_number"]},{rec["name"]},{rec["type"]},{rec["result"]},{ttl_str},{rec["static"]}')

    def __decrement_ttl(self):
        while True:
            with self.lock:
                for rec in self.records:
                    if rec["static"] == 0 and rec["ttl"] is not None and rec["ttl"] > 0:
                        rec["ttl"] -= 1
                self.__remove_expired_records()
            time.sleep(1)

    def __remove_expired_records(self):
        kept = []
        for rec in self.records:
            if rec["static"] == 0 and rec["ttl"] is not None and rec["ttl"] <= 0:
                continue
            kept.append(rec)
        self.records = kept
        # Renumber so record_no stays sequential
        for i, rec in enumerate(self.records):
            rec["record_number"] = i
        self.record_number = len(self.records)


class DNSTypes:
    """
    A class to manage DNS query types and their corresponding codes.

    Examples:
    >>> DNSTypes.get_type_code('A')
    8
    >>> DNSTypes.get_type_name(0b0100)
    'AAAA'
    """

    name_to_code = {
        "A": 0b1000,
        "AAAA": 0b0100,
        "CNAME": 0b0010,
        "NS": 0b0001,
    }

    code_to_name = {code: name for name, code in name_to_code.items()}

    @staticmethod
    def get_type_code(type_name: str):
        """Gets the code for the given DNS query type name, or None"""
        return DNSTypes.name_to_code.get(type_name, None)

    @staticmethod
    def get_type_name(type_code: int):
        """Gets the DNS query type name for the given code, or None"""
        return DNSTypes.code_to_name.get(type_code, None)


class UDPConnection:
    """A class to handle UDP socket communication, capable of acting as both a client and a server."""

    def __init__(self, timeout: int = 1):
        """Initializes the UDPConnection instance with a timeout. Defaults to 1."""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.settimeout(timeout)
        self.is_bound = False

    def send_message(self, message: str, address: tuple[str, int]):
        """Sends a message to the specified address."""
        self.socket.sendto(message.encode(), address)

    def receive_message(self):
        """
        Receives a message from the socket.

        Returns:
            tuple (data, address): The received message and the address it came from.

        Raises:
            KeyboardInterrupt: If the program is interrupted manually.
        """
    try:
        data, address = self.socket.recvfrom(4096)
        return data.decode(), address
        except socket.timeout:
            raise
        except OSError as e:
            if e.errno == errno.ECONNRESET:
                print("Error: Unable to reach the other socket. It might not be up and running.")
            else:
                print(f"Socket error: {e}")
            self.close()
            sys.exit(1)
        except KeyboardInterrupt:
            raise

    def bind(self, address: tuple[str, int]):
        """Binds the socket to the given address. This means it will be a server."""
        if self.is_bound:
            print(f"Socket is already bound to address: {self.socket.getsockname()}")
            return
        self.socket.bind(address)
        self.is_bound = True

    def close(self):
        """Closes the UDP socket."""
        self.socket.close()


if __name__ == "__main__":
    main()
