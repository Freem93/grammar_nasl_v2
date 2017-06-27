#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73950);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/05/12 10:51:42 $");

  script_cve_id("CVE-2014-3220");
  script_bugtraq_id(67191);
  script_osvdb_id(106532);
  script_xref(name:"IAVB", value:"2014-B-0051");

  script_name(english:"F5 Networks BIG-IQ Configuration Utility Privilege Escalation");
  script_summary(english:"Checks BIG-IQ version.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the remote F5 Networks BIG-IQ device
is affected by a privilege escalation vulnerability that allows
remote, authenticated users to change the password of other users
(such as the default 'root' user) via a specially crafted request to
the web configuration utility. This is due to a flaw in the
'/mgmt/shared/authz/users/' script.");
  # http://support.f5.com/kb/en-us/solutions/public/15000/200/sol15229.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c8d05021");
  # http://volatile-minds.blogspot.com/2014/05/f5-big-iq-v41020130-authenticated.html
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?b3ef1cac");
  script_set_attribute(attribute:"solution", value:"Upgrade to BIG-IQ version 4.2.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-iq");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("f5_bigiq_detect.nbin");
  script_require_keys("Host/BIG-IQ/version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

version = get_kb_item_or_exit("Host/BIG-IQ/version");

port = get_kb_item("Host/BIG-IQ-CU/detected");
if (isnull(port))
{
  if (report_paranoia < 2) audit(AUDIT_PARANOID);
  port = 0;
}

# 4.0.0 - 4.1.0 affected
if (version =~ "^4\.[01]\.0(\.|$)")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 4.2.0' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "BIG-IQ", version);
