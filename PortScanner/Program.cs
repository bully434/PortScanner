using System.Linq;
using System.Net;
using NMAP;

namespace PortScanner
{
    internal class Program
    {
        public static void Main(string[] args)
        {
            var ipAddrs = Dns.GetHostAddresses("cs.usu.edu.ru");
            var ports = Enumerable.Range(10,110).ToArray();

            var scanner = new ParallelScaner();
            scanner.Scan(ipAddrs, ports).Wait();
        }
    }
}