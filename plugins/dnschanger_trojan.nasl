#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");


if (description)
{
  script_id(58182);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/09/24 21:08:38 $");

  script_name(english:"DNSChanger Malware Detection");
  script_summary(english:"Looks for known bad DNS servers in use");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host may be infected with malware."
  );
  script_set_attribute(
    attribute:"description",
    value:
"DNSChanger appears to be installed on the remote host.  This malware
configures the host to use rogue DNS servers, which could cause
requests for legitimate websites and hostnames to be routed to
attacker controlled machines. 

Nessus determines the likelihood of infection by comparing the list of
DNS servers configured on the host to a list of IP addresses
associated with this malware.  More information can be found in the
linked references."
  );
  # http://www.fbi.gov/news/stories/2011/november/malware_110911/DNS-changer-malware.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2fe8e345");
  script_set_attribute(attribute:"see_also", value:"http://www.f-secure.com/v-descs/dnschang.shtml");
  # http://www.symantec.com/security_response/writeup.jsp?docid=2008-120318-5914-99&tabid=2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bf883954");
  script_set_attribute(
    attribute:"solution",
    value:
"Update the host's antivirus software, clean the host, and scan again
to ensure the Trojan's removal.  If symptoms persist, re-installation 
of the infected host is recommended."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/01");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"malware", value:"true"); 
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_dns_servers.nasl", "macosx_dns_servers.nasl");
  script_require_ports("SMB/nameservers", "resolv.conf/nameserver");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

##
# Determines if an IP address is falls within a given range
#
# @param ip IP address to check
# @param min low end of the range (IP address)
# @param max high end of the range (IP address)
#
# @remark this function doesn't do any error checking on the given arguments
# @return TRUE if 'ip' is between 'min' and 'max' (inclusive),
#         FALSE otherwise
##
function _ip_in_range(ip, min, max)
{
  local_var i;
  ip = split(ip, sep:'.', keep:FALSE);
  min = split(min, sep:'.', keep:FALSE);
  max = split(max, sep:'.', keep:FALSE);

  for (i = 0; i < max_index(ip); i++)
  {
    ip[i] = int(ip[i]);
    min[i] = int(min[i]);
    max[i] = int(max[i]);

    if (ip[i] < min[i] || ip[i] > max[i])
      return FALSE;
    if (ip[i] >= min[i] && ip[i] < max[i])
      return TRUE;
    if (ip[i] > min[i] && ip[i] <= max[i])
      return TRUE;
  }

  return TRUE; # ip == min == max
}

ip_addrs = get_kb_list('resolv.conf/nameserver');
if (isnull(ip_addrs))
  ip_addrs = get_kb_list('SMB/nameserver/*');

if (isnull(ip_addrs))
  exit(0, 'No Windows or Mac DNS servers were enumerated.');

ip_addrs = list_uniq(make_list(ip_addrs));
bad_ips = make_list();

foreach ip_addr (ip_addrs)
{
  # Rare cases the SMB/nameserver/ could return a null or empty address
  if(empty_or_null(ip_addr)) continue;

  # checks each name server IP address against a list of known bads associated with this malware
  if (
    # source: FBI advisory
    _ip_in_range(ip:ip_addr, min:'85.255.112.0', max:'85.255.127.255') ||
    _ip_in_range(ip:ip_addr, min:'67.210.0.0', max:'67.210.15.255') ||
    _ip_in_range(ip:ip_addr, min:'93.188.160.0', max:'93.188.167.255') ||
    _ip_in_range(ip:ip_addr, min:'77.67.83.0', max:'77.67.83.255') ||
    _ip_in_range(ip:ip_addr, min:'213.109.64.0', max:'213.109.79.255') ||
    _ip_in_range(ip:ip_addr, min:'64.28.176.0', max:'64.28.191.255') ||

    # source: F-Secure advisory
    ip == '193.227.227.218'
  )
  {
    bad_ips = make_list(bad_ips, ip_addr);
  }
}

if (max_index(bad_ips) == 0)
  exit(0, 'The host is not affected.');

if (report_verbosity > 0)
{
  report =
    '\nThe following name servers associated with the DNSChanger malware are in\n' +
    'use on the remote host :\n\n' +
    join(bad_ips, sep:'\n') + '\n';
  security_warning(port:0, extra:report);
}
else security_warning(0);
