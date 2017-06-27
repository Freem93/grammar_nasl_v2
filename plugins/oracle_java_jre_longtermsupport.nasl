#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71462);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/12/16 18:56:37 $");

  script_name(english:"Oracle Java JRE Premier Support and Extended Support Version Detection");
  script_summary(english:"Checks if any Oracle Java JRE installs require long-term support.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains one or more versions of the Oracle Java JRE
that require long-term support.");
  script_set_attribute(attribute:"description", value:
"According to its version, there is at least one install of Oracle
(formerly Sun) Java JRE that is potentially under either Premier Support
or Extended Support. 

Note that both support programs require vendor contracts.  Premier
Support provides upgrades and security fixes for five years after the
general availability (GA) date.  Extended Support provides upgrades and
security fixes for three years after Premier Support ends.");
  script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technetwork/java/eol-135779.html");
  script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/us/support/lifetime-support-068561.html");
  script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/us/support/lifetime-support/index.html");
  script_set_attribute(attribute:"solution", value:
"To continue receiving updates and security fixes, contact the vendor
regarding Premier Support or Extended Support contracts.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("oracle_java_jre_unsupported.nasl");
  script_require_keys("SMB/Java/JRE/Installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

info = "";

# Check Premier Support versions first
jre_premier_support_installs = get_kb_list("Java/JRE/premier_support/*");

if (jre_premier_support_installs)
{
  foreach path_ver (keys(jre_premier_support_installs))
  {
    pv = path_ver - "Java/JRE/premier_support/";
    pieces = split(pv, sep:"/", keep:FALSE);
    info += '\n' +
            '\n  Path          : ' + pieces[0] +
            '\n  Version       : ' + pieces[1] +
            '\n  Support dates : ' + jre_premier_support_installs[path_ver];
  }
}

if (info)
  info = '\n' + 'The following Java JRE installs are in Premier Support status : ' + info;

# Check Extended Support versions next
extended_info = "";
jre_extended_support_installs = get_kb_list("Java/JRE/extended_support/*");

if (jre_extended_support_installs)
{
  foreach path_ver (keys(jre_extended_support_installs))
  {
    pv = path_ver - "Java/JRE/extended_support/";
    pieces = split(pv, sep:"/", keep:FALSE);
    extended_info += '\n' +
            '\n  Path          : ' + pieces[0] +
            '\n  Version       : ' + pieces[1] +
            '\n  Support dates : ' + jre_extended_support_installs[path_ver];
  }
}

if (extended_info)
  info += '\n' +
          '\n' + 'The following Java JRE installs are in Extended Support status : ' + extended_info;

if (info)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
    security_note(port:port, extra:info);
  else
    security_note(port);
}
else audit(AUDIT_NOT_INST, "Oracle Java JRE under Premier Support or Extended Support");
