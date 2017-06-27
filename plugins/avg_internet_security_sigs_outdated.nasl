#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(88932);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/03/21 17:12:55 $");

  script_name(english:"AVG Internet Security Out-of-Date");
  script_summary(english:"Checks if the latest AVG Internet Security is being used.");

  script_set_attribute(attribute:"synopsis", value:
"The remote antivirus application is not up to date.");
  script_set_attribute(attribute:"description",value:
"The remote host is running AVG Internet Security. However, the
installation version, or its virus definition database, is not up to
date. Using an out-of-date installation or virus database may allow
this host, or potentially other hosts (e.g., a mail or file server),
to become infected by a virus or worm.");
  script_set_attribute(attribute:"see_also", value:"http://free.avg.com/us-en/download-update");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of AVG Internet Security and make sure
the virus definition database is also kept up to date.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:avg:internet_security");                                          
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("avg_internet_security_installed.nbin");
  script_require_keys("installed_sw/AVG Internet Security");

  exit(0);
}


include("antivirus.inc");
include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");
include("install_func.inc");

app = "AVG Internet Security";
install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
path    = install["path"];
version = split(install["version"], sep:'.', keep:FALSE);
mversion = version[0];
pversion = version[1];
vdbc = install["vdbCore"];
vdba = install["vdbAvi"];

info = get_av_info("avg_is");
if (empty_or_null(info)) exit(1, "Failed to get AVG IS signature info from antivirus.inc.");
if (empty_or_null(vdbc)) exit(1, "Failed to get AVG Virus DB Core Version from antivirus.inc");
if (empty_or_null(vdba)) exit(1, "Failed to get AVG Virus DB Avi Version from antivirus.inc");
last_prod = info[mversion]["latest_prod_ver"];
last_core = info[mversion]["core_sigs_ver"];
last_avi  = info[mversion]["incremental_sigs_ver"];

ooDate = FALSE;
pvBad = FALSE;
vdBad = FALSE;
if (pversion < int(last_prod))
{
  ooDate = TRUE;
  pvBad = TRUE;
}
if (vdbc < int(last_core) || (vdbc == int(last_core) && vdba < int(last_avi)))
{
  ooDate = TRUE;
  vdBad = TRUE;
}


if (ooDate)
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;
  # Reporting
  ri = make_array();
  fo = make_list();
  if(pvBad)
  {
    ri["Installed Product Version"] = mversion + "." + pversion;
    fo = make_list(fo, "Installed Product Version");

    ri["Latest Product Version"] = last_prod;
    fo = make_list(fo, "Latest Product Version");
  }

  if(vdBad)
  {
    ri["Installed DB Version"] = vdbc + "/" + vdba;
    fo = make_list(fo, "Installed DB Version");
    ri["Latest DB Version"] = last_core + "/" + last_avi;
    fo = make_list(fo, "Latest DB Version");
  }

  report =
      '\nThe remote host has an outdated version of AVG ' + 
      '\nor AVG Internet Security virus database:\n'+
      report_items_str(report_items:ri, ordered_fields:fo);
  security_report_v4(
          port      : port,
          severity  : SECURITY_HOLE,
          extra     : report
  );
}
else exit(0, 'AVG Internet Security virus database version ' + vdbc + "/" + vdba + ' is up to date.');
