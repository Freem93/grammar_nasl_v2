#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
 script_id(27525);
 script_version("$Revision: 1.29 $");
 script_cvs_date("$Date: 2016/12/07 20:46:54 $");

 script_name(english:"Microsoft Office Service Pack Out of Date");
 script_summary(english:"Determines the remote Office SP");

 script_set_attribute(attribute:"synopsis", value:"The remote office suite is not up to date.");
 script_set_attribute(attribute:"description", value:
"The remote version of Microsoft Office has no service pack or the one
installed is no longer supported.");
  # http://web.archive.org/web/20070903200039/http://support.microsoft.com/gp/lifesupsps
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e33c553d");
 script_set_attribute(attribute:"solution", value:"Install the latest service pack.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");


 script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/23");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows");

 script_dependencies("office_installed.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}

#
include("misc_func.inc");

office_sp["2000"] = 3;
office_sp["XP"] = 3;
office_sp["2003"] = 3;
office_sp["2007"] = 3;
office_sp["2010"] = 2;
office_sp["2013"] = 1;

office_min_sp["2000"] = 3;
office_min_sp["XP"] = 3;
office_min_sp["2003"] = 3;
office_min_sp["2007"] = 3;
office_min_sp["2010"] = 2;
office_min_sp["2013"] = 0;

report = NULL;

l = get_kb_list_or_exit("SMB/Office/*/SP");
foreach item (keys(l))
{
  version = item - 'SMB/Office/' - '/SP';
  sp = l[item];

  if (sp == 0)
    report_detail = "no service pack";
  else
    report_detail = "Service Pack " + sp;

  if (sp < office_min_sp[version])
  {
    report +=
      '\n' +
      'The remote Microsoft Office ' + version + ' system has ' + report_detail + ' applied.\n' +
      'The system should have Office ' + version + ' Service Pack ' + office_sp[version] + ' installed.\n';
  }
}

if ( report )
 security_hole(extra:report, port:get_kb_item("SMB/transport"));
