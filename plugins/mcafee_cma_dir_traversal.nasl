#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22046);
  script_version("$Revision: 1.25 $");
  script_cvs_date("$Date: 2016/11/28 21:52:56 $");

  script_cve_id("CVE-2006-3623");
  script_bugtraq_id(18979);
  script_osvdb_id(27158);

  script_name(english:"McAfee Common Management Agent Traversal Arbitrary File Write");
  script_summary(english:"Checks the version of McAfee CMA.");

  script_set_attribute(attribute:"synopsis", value:
"A security management service running on the remote host is affected
by a directory traversal vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the McAfee Common Management Agent (CMA)
running on the remote host is affected by a directory traversal
vulnerability in the Framework Service component due to improper
sanitization of user-supplied input. An unauthenticated, remote
attacker can exploit this, via a specially crafted request, to write
arbitrary files outside of the web path.");
  # https://kc.mcafee.com/resources/sites/MCAFEE/content/live/CORP_KNOWLEDGEBASE/55000/KB55256/en_US/cma_security_bltn.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?796abf12");
  script_set_attribute(attribute:"solution", value:
"Upgrade to McAfee Common Management Agent version 3.5.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:common_management_agent");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:epolicy_orchestrator");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");

  script_dependencies("mcafee_cma_detect.nasl");
  script_require_ports("Services/www", 8081);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

appname = "McAfee Agent";
port = get_http_port(default:8081, embedded: 1);

install = get_single_install(app_name:appname, port:port, exit_if_unknown_ver:TRUE);
ver = install['version'];

ver_fields = split(ver, sep:'.', keep:FALSE);
major = int(ver_fields[0]);
minor = int(ver_fields[1]);
rev = int(ver_fields[2]);
update = int(ver_fields[3]);

fix = '';

# There's a problem if it's under 3.5.5.438.
if (major < 3 ||
   (major == 3 && minor < 5) ||
   (major == 3 && minor == 5 && rev < 5) ||
   (major == 3 && minor == 5 && rev == 5 && update < 438))
  fix = '3.5.5.438';

if(fix != '')
{
  report =
    '\n  Installed Version : ' + ver +
    '\n  Fixed Version     : ' + fix + '\n';
  security_report_v4(severity:SECURITY_WARNING, port:port, extra:report);
}
else audit(AUDIT_LISTEN_NOT_VULN, "McAfee Common Management Agent", port, ver);
