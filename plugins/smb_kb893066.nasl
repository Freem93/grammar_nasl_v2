#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(18028);
 script_version("$Revision: 1.34 $");
 script_cvs_date("$Date: 2016/05/06 17:11:37 $");

 script_cve_id("CVE-2005-0048", "CVE-2004-0790", "CVE-2004-1060", "CVE-2004-0230", "CVE-2005-0688");
 script_bugtraq_id(13124, 13116);
 script_osvdb_id(14578, 15457, 15463, 15619, 4030);
 script_xref(name:"MSFT", value:"MS05-019");

 script_name(english:"MS05-019: Vulnerabilities in TCP/IP Could Allow Remote Code Execution (893066) (uncredentialed check)");
 script_summary(english:"Checks for hotfix KB893066");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host due to a flaw in the
TCP/IP stack.");
 script_set_attribute(attribute:"description", value:
"The remote host runs a version of Windows that has a flaw in its
TCP/IP stack.

The flaw may allow an attacker to execute arbitrary code with SYSTEM
privileges on the remote host or to perform a denial of service attack
against the remote host.

Proof of concept code is available to perform a denial of service
attack against a vulnerable system.");
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms05-019");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Windows 2000, XP and 2003.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/04/20");
 script_set_attribute(attribute:"plugin_publication_date", value:"2005/04/12");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows");

 script_dependencies("tcp_seq_window.nasl", "os_fingerprint.nasl");
 script_require_keys("TCP/seq_window_flaw", "Host/OS", "Settings/ParanoidReport");
 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

os = get_kb_item_or_exit("Host/OS") ;

conf = get_kb_item_or_exit("Host/OS/Confidence");
if (conf <= 70) exit(1, "Can't determine the host's OS with sufficient confidence.");

if ("Windows" >!< os) exit(0, "The host is not running Windows.");
if ("Windows 4.0" >< os) exit(0, "Windows NT is not reported to be affected.");
if ("Windows Server 2003 Service Pack" >< os) exit(0, "Windows 2003 SP1 and later are not reported to be affected.");

if (ereg(pattern:"Windows (95|98|ME|XP|Server 2003)", string:os))
{
  if (get_kb_item("TCP/seq_window_flaw"))
  {
   security_hole(port:get_kb_item("SMB/transport"));
   exit(0);
  }
  else exit(0, "The host is not affected.");
}
else exit(0, "The host is not running one of the versions of Windows reportedly affected.");
