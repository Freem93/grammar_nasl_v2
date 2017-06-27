#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70942);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/11/18 20:50:17 $");

  script_bugtraq_id(62110);
  script_osvdb_id(96796);
  script_xref(name:"EDB-ID", value:"28056");

  script_name(english:"MikroTik RouterOS 5.x < 5.26 / 6.x < 6.3 sshd Unspecified Remote Heap Corruption");
  script_summary(english:"Checks RouterOS version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote networking device is affected by a heap corruption
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version, the remote networking device
is running a version of MikroTik 5.x before 5.26 or 6.x before 6.3.
It, therefore, reportedly has a heap corruption vulnerability in its
sshd component that can be leveraged by an unauthenticated, remote
attacker to crash the SSH service."
  );
  # http://kingcope.wordpress.com/2013/09/02/mikrotik-routeros-5-and-6-sshd-remote-preauth-heap-corruption/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?38c2e68b");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/528394/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://forum.mikrotik.com/viewtopic.php?p=384465#p384465");
  script_set_attribute(attribute:"see_also", value:"http://www.mikrotik.com/download/CHANGELOG_5");
  script_set_attribute(attribute:"see_also", value:"http://www.mikrotik.com/download/CHANGELOG_6");
  script_set_attribute(attribute:"solution", value:"Upgrade to MikroTik RouterOS 5.26 / 6.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mikrotik:routeros");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("mikrotik_detect.nasl", "ssh_detect.nasl");
  script_require_keys("MikroTik/RouterOS/Version");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");


version = get_kb_item_or_exit("MikroTik/RouterOS/Version");
if (version !~ "^[56]\.") audit(AUDIT_OS_RELEASE_NOT, "MikroTik RouterOS", "5.x / 6.x", version);

port = 0;
if (report_paranoia < 2)
{
  port = get_service(svc:"ssh", default:22, exit_on_fail:TRUE);
  banner = get_kb_item_or_exit("SSH/banner/"+port);
  if ("ROSSSH" >!< banner) audit(AUDIT_NOT_LISTEN, 'Mikrotik RouterOS sshd', port);
}


if (
  version =~ "^5\.([0-9]|1[0-9]|2[0-5])($|[^0-9])" ||
  version =~ "^6\.[0-2]($|[^0-9])"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 5.26 / 6.3' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_OS_RELEASE_NOT, "MikroTik RouterOS", version);
