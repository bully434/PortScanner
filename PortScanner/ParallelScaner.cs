using System;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using log4net;

namespace NMAP
{
    public class ParallelScaner
    {
        protected virtual ILog log => LogManager.GetLogger(typeof(ParallelScaner));

        public async Task Scan(IPAddress[] ipAdrrs, int[] ports)
        {
            await Task.WhenAll(ipAdrrs.Select(ipAddr => (ipAddr, PingAddr(ipAddr)))
                .Select(async x=>
                {
                    var (ipAddress, pingResult) = x;
                    if (await pingResult != IPStatus.Success) return;
                    ports.ToList().ForEach(p => CheckUDPPort(ipAddress, p));
                    var nestedTasks = ports.Select(port => CheckPort(ipAddress, port));
                    await Task.WhenAll(nestedTasks);
                }));
        }
        
        protected async Task CheckUDPPort(IPAddress ipAddr, int port, int timeout = 3000)
        {
            using (var udpClient = new UdpClient())
            {
                udpClient.Connect(ipAddr, port);

                udpClient.Client.ReceiveTimeout = timeout;

                Byte[] sendBytes = Encoding.ASCII.GetBytes("Are you open?");
                udpClient.Send(sendBytes, sendBytes.Length);

                var result = udpClient.ReceiveAsync();
                if (await Task.WhenAny(result, Task.Delay(timeout)) == result)
                {
                    log.Info($"Checked {ipAddr}:{port} - UDP - OPEN");
                }

                udpClient.Close();
            }
        }

        protected async Task<IPStatus> PingAddr(IPAddress ipAddr, int timeout = 3000)
        {
            log.Info($"Pinging {ipAddr}");
            using (var ping = new Ping())
            {
                var sendTask = await ping.SendPingAsync(ipAddr, timeout);
                return sendTask.Status;
            }
        }

        protected async Task CheckPort(IPAddress ipAddr, int port, int timeout = 3000)
        {
            using (var tcpClient = new TcpClient())
            {

                var connectTask = await tcpClient.ConnectAsync(ipAddr, port, timeout);

                PortStatus portStatus;
                switch (connectTask.Status)
                {
                    case TaskStatus.RanToCompletion:
                        portStatus = PortStatus.OPEN;
                        break;
                    case TaskStatus.Faulted:
                        portStatus = PortStatus.CLOSED;
                        break;
                    default:
                        portStatus = PortStatus.FILTERED;
                        break;
                }
                if (portStatus == PortStatus.OPEN)
                {
                    var protocol = GetProtocol(port);
                    log.Info($"Checked {ipAddr}:{port} - TCP - {portStatus}. Protocol: {protocol}");
                }
            }
        }
    }
}