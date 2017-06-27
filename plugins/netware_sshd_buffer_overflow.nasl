#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(44066);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2012/01/31 18:56:39 $");

  script_bugtraq_id(42875);
  script_osvdb_id(67743);
  script_xref(name:"EDB-ID", value:"14866");

  script_name(english:"Novell NetWare 6.5 OpenSSH Remote Stack Buffer Overflow");
  script_summary(english:"Checks if OpenSSH is installed and the system is NW 6.5");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The SSH server running on the remote host has a buffer overflow
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of OpenSSH running on the remote Novell NetWare host has
a stack-based buffer overflow vulnerability.  When attempting to
resolve an absolute path on the server, data is copied into a 512 byte
buffer without any bounds checking.  A remote, authenticated attacker
could exploit this to execute arbitrary code."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/513483/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-169/");
  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/support/viewContent.do?externalId=7006756");
  # http://dvlabs.tippingpoint.com/blog/2010/09/01/zdi-10-169-on-exploitability
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?240e3831");
  script_set_attribute(
    attribute:"solution",
    value:"There is no fix available, and the software is no longer supported."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/04");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:netware:6.5");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Netware");

  script_copyright(english:"This script is Copyright (C) 2011-2012 Tenable Network Security, Inc.");

  script_dependencies("os_fingerprint.nasl", "snmp_software.nasl", "ssh_detect.nasl");
  script_require_keys("Host/OS");
  script_require_ports("SNMP/hrSWInstalledName", "Services/ssh");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

os = get_kb_item_or_exit('Host/OS');
os = tolower(os);

# http://forums.novell.com/forums/novell/novell-product-discussion-forums/open-enterprise-server/oes-netware/oes-nw-administration-tools/362046-netware-server-basic-inventory-report-post1743059.html
# 5.70.xx = Netware 6.5 SP xx
if ('novell netware 5.7' >!< os && 'novell netware 6.5' >!< os)
  exit(0, 'The host doesn\'t look like NetWare 6.5.');

# first check to see if SSH is running
port = get_kb_item("Services/ssh");

# if not, see if it's installed
if (isnull(port))
{
  sw = get_kb_list('SNMP/hrSWInstalledName');

  foreach pkg (sw)
  {
    if ('OpenSSH' >< pkg)
    {
      port = 0;
      break;
    }
  }
}

if (isnull(port))
  exit(0, 'SSH doesn\'t appear to be installed.');
else
  security_hole(port);

