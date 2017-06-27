#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69428);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/08/22 12:22:40 $");

  script_cve_id("CVE-2013-0931");
  script_bugtraq_id(58248);
  script_osvdb_id(90743);
  script_xref(name:"IAVB", value:"2013-B-0019");

  script_name(english:"RSA Authentication Agent 7.1.x < 7.1.2 Authentication Bypass");
  script_summary(english:"Checks version of RSA Authentication Agent");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an authentication application installed
that is affected by an authentication bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of RSA Authentication Agent installed on the remote 
Windows host is 7.1.x prior to 7.1.2.  Such versions contain a flaw 
that may allow an attacker to bypass the passcode mechanism on systems 
configured with the Quick PIN unlock.");
  # http://packetstormsecurity.com/files/120606/RSA-Authentication-Agent-7.1.1-Access-Bypass.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?66ed4efe");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/525862/30/0/threaded");
  script_set_attribute(attribute:"solution", value:"Upgrade to RSA Authentication Agent 7.1.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:rsa:authentication_agent_for_windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("rsa_authentication_agent_installed.nasl");
  script_require_keys("SMB/RSA Authentication Agent/Version", "SMB/RSA Authentication Agent/Path");
  
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("SMB/RSA Authentication Agent/Version");
path = get_kb_item_or_exit("SMB/RSA Authentication Agent/Path");

if (version =~ '^7\\.1\\.' && ver_compare(ver:version, fix:'7.1.2', strict:FALSE) < 0)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 7.1.2\n';

    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, 'RSA Authentication Agent', version, path);
