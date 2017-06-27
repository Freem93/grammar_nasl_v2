#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(14611);
 script_version("$Revision: 1.32 $");
 script_cvs_date("$Date: 2017/04/25 14:28:28 $");

 script_name(english:"AIX Technology Level Out of Date");
 script_summary(english:"Check for outdated Technology Level");

 script_set_attribute(attribute:"synopsis", value:"The remote operating system is out of date.");
 script_set_attribute(attribute:"description", value:
"The remote AIX operating system is lagging behind its official
Technology Level (TL) and may therefore be missing critical security
patches.");
 script_set_attribute(attribute:"see_also", value:"https://www-945.ibm.com/support/fixcentral/");
 script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=isg3T1012517");
 script_set_attribute(attribute:"solution", value:"Update to a current AIX Technology Level.");
 script_set_attribute(attribute:"risk_factor", value:"High");

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/01");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2017 Tenable Network Security, Inc.");
 script_family(english:"AIX Local Security Checks");

 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/AIX/oslevel");

 exit(0);
}

include("global_settings.inc");

# nb: See <https://www-304.ibm.com/support/docview.wss?uid=isg3T1012517> for
#     info about TLs for which fixes are available.
aix_tl = make_array();      aix_tl_min = make_array();
aix_tl[7100] = 3;           aix_tl_min[7100] = 2;
aix_tl[6100] = 9;           aix_tl_min[6100] = 8;

aix_ver = make_array();
aix_ver[7100] = "7.1";
aix_ver[6100] = "6.1";
aix_ver[5300] = "5.3";
aix_ver[5200] = "5.2";
aix_ver[5100] = "5.1";


buf = get_kb_item("Host/AIX/oslevel");
if (!buf) exit(0, "The 'Host/AIX/oslevel' KB item is missing.");

v = split(buf, sep:"-",keep: 0);
if (isnull(v)) exit(0);

osversion = int(v[0]);
level = int(chomp(v[1]));

if (aix_ver[osversion]) aix = aix_ver[osversion];
else aix = osversion;

if (!isnull(aix_tl[osversion]))
{
  if (level < aix_tl_min[osversion])
  {
    if (report_verbosity > 0)
    {
      report =
        '\n  AIX version                 : ' + aix +
        '\n  Installed Technology Level  : ' + level;

      if (aix_tl_min[osversion] < aix_tl[osversion])
        report +=
          '\n  Supported Technology Levels : ' + aix_tl_min[osversion] + ' - ' + aix_tl[osversion] + '\n';
      else
        report +=
          '\n  Supported Technology Level  : ' + aix_tl[osversion] + '\n';
      security_hole(port:0, extra:report);
    }
    else security_hole(0);
    exit(0);
  }
  else exit(0, "Fixes are currently available for AIX "+aix+" TL"+level+".");
}
else exit(0, "Nessus does not have any info about currently supported Technology Levels for AIX "+aix+".");
