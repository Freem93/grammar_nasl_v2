#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62759);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/12/21 22:04:46 $");

  script_cve_id("CVE-2012-3268");
  script_bugtraq_id(56183);
  script_osvdb_id(86571);
  script_xref(name:"CERT", value:"225404");

  script_name(english:"HP/H3C and Huawei SNMP User Data Information Disclosure");
  script_summary(english:"Tries to enumerate the list of users");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote networking device has an information disclosure
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host allows SNMP read-only access to either h3c-user.mib or
hh3c-user.mib.  These MIBs contain information such as usernames,
passwords, and user privileges.  A remote attacker with a valid
read-only community string could exploit this to enumerate usernames and
passwords, which could lead to administrative access to the device."
  );
  # http://grutztopia.jingojango.net/2012/10/hph3c-and-huawei-snmp-weak-access-to.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a4b8d1ca");
  # https://h20565.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c03515685
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?97e345d2");
  script_set_attribute(
    attribute:"solution",
    value:
"For HP devices, install the appropriate software update to fix this
issue.  If an update is not available, use one of the workarounds listed
in the referenced advisories."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SNMP");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("snmp_settings.nasl", "snmp_sysDesc.nasl");
  script_require_keys("SNMP/community", "SNMP/sysDesc");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("snmp_func.inc");

sysdesc = get_kb_item_or_exit("SNMP/sysDesc");
if (sysdesc !~ 'H3C|Huawei')
  audit(AUDIT_HOST_NOT, 'a H3C or Huawei device');

community = get_kb_item_or_exit("SNMP/community");
port = get_kb_item("SNMP/port");
if (!port) port = 161;

if (!get_udp_port_state(port))
  audit(AUDIT_PORT_CLOSED, port, 'UDP');

oids = make_list(
  '1.3.6.1.4.1.2011.10.2.12.1.1.1.1', # h3cUserName (old)
  '1.3.6.1.4.1.25506.2.12.1.1.1.1'    # hh3cUserName (new)
);

foreach oid (oids)
{
  soc = open_sock_udp(port);
  if (!soc)
    audit(AUDIT_SOCK_FAIL, port, 'UDP');
  
  users = scan_snmp_string(socket:soc, community:community, oid:oid);
  close(soc);
  
  if (strlen(users))
  {
    if (report_verbosity > 0)
    {
      report = '\nNessus was able to get a list of users :\n\n' + users;
      security_warning(port:port, extra:report, protocol:"udp");
    }
    else security_warning(port:port, protocol:"udp");

    exit(0);
  }
}

audit(AUDIT_HOST_NOT, 'affected');
