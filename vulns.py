import ssl
import requests
from twisted.internet import reactor, ssl
from twisted.internet.protocol import ReconnectingClientFactory
from twisted.words.protocols.irc import IRCClient


class VulnBot(IRCClient):
    nickname = "VulnBot"
    channel = "#blcknd"

    def connectionMade(self):
        print(f"Connected as {self.nickname}")
        IRCClient.connectionMade(self)

    def signedOn(self):
        print(f"Joining {self.channel}")
        self.join(self.channel)

    def joined(self, channel):
        print(f"[Joined {self.channel}]")

    def privmsg(self, user, channel, message):
        user = user.split('!', 1)[0]
        print(f"{user}: {message}")

        if message.startswith("!cve"):
            cve_id = message.split()[1]
            cve_info = self.get_cve_info(cve_id)
            self.msg(channel, cve_info)

        elif message.startswith("!owasp"):
            self.msg(channel, "https://owasp.org/")

        elif message.startswith("!exploitdb"):
            self.msg(channel, "https://www.exploit-db.com/")

        elif message.startswith("!search"):
            query = message.split(" ", 1)[1]
            results = self.search_cve(query)
            if len(results) > 0:
                self.msg(channel, f"Search results for '{query}': {', '.join(results)}")
            else:
                self.msg(channel, f"No results found for '{query}'")

    def get_cve_info(self, cve_id):
        cve_api_url = f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_id}"
        try:
            response = requests.get(cve_api_url)
            if response.status_code == 200:
                cve_info = response.json()["result"]["CVE_Items"][0]["cve"]["description"]["description_data"][0]["value"]
                return cve_info
            else:
                return f"Error fetching CVE information for {cve_id}."
        except Exception as e:
            print(f"Error fetching CVE information for {cve_id}: {e}")
            return f"Error fetching CVE information for {cve_id}."

    def search_cve(self, query):
        cve_api_url = f"https://services.nvd.nist.gov/rest/json/cves/1.0"
        try:
            response = requests.get(cve_api_url, params={"keyword": query})
            if response.status_code == 200:
                results = response.json()["result"]["CVE_Items"]
                return [result["cve"]["CVE_data_meta"]["ID"] for result in results]
            else:
                return []
        except Exception as e:
            print(f"Error searching for CVEs with query '{query}': {e}")
            return []

class VulnBotFactory(ReconnectingClientFactory):
    protocol = VulnBot

    def clientConnectionLost(self, connector, reason):
        print(f"Lost connection. Reason: [{reason}]")
        ReconnectingClientFactory.clientConnectionLost(self, connector, reason)

    def clientConnectionFailed(self, connector, reason):
        print(f"Connection failed. Reason: [{reason}]")
        ReconnectingClientFactory.clientConnectionFailed(self, connector, reason)


if __name__ == "__main__":
    reactor.connectSSL("irc.blcknd.net", 6697, VulnBotFactory(), ssl.ClientContextFactory())
    reactor.run()
