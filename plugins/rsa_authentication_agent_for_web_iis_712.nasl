#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70746);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/11/05 00:55:53 $");

  script_cve_id("CVE-2013-3280");
  script_bugtraq_id(63303);
  script_osvdb_id(98898);

  script_name(english:"RSA Authentication Agent for Web for IIS 7.1.x < 7.1.2 Filter Bypass");
  script_summary(english:"Checks version of RSA Authentication Agent for Web for IIS");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an authentication agent installed that is
affected by a filter bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of RSA Authentication Agent for Web for IIS is 7.1.x prior
to 7.1.2.  Such versions are potentially affected by an unspecified
filter bypass vulnerability.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/529394/30/0/threaded");
  script_set_attribute(attribute:"solution", value:"Upgrade to RSA Authentication Agent for Web for IIS 7.1.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/04");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:rsa_authentication_agent");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("rsa_authentication_agent_for_web_iis.nbin");
  script_require_keys("SMB/RSA Authentication Agent for Web for IIS/Path", "SMB/RSA Authentication Agent for Web for IIS/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("SMB/RSA Authentication Agent for Web for IIS/Version");
path = get_kb_item_or_exit("SMB/RSA Authentication Agent for Web for IIS/Path");

if (version =~ '^7\\.1\\.' && ver_compare(ver:version, fix:'7.1.2.98') < 0)
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 7.1.2.98\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
audit(AUDIT_INST_PATH_NOT_VULN, 'RSA Authentication Agent for Web for IIS', version, path);
