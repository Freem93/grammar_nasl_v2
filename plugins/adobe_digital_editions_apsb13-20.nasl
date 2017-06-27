#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72171);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/01/28 20:38:38 $");

  script_cve_id("CVE-2013-1377");
  script_bugtraq_id(61528);
  script_osvdb_id(95828);

  script_name(english:"Adobe Digital Editions 2.0.0 'rmsdk_wrapper.dll' Memory Corruption (APSB13-20)");
  script_summary(english:"Checks version of Adobe Digital Editions");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The version of Adobe Digital Editions on the remote Windows host is
affected by a memory corruption vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Adobe Digital Editions installed on the remote
host is 2.0.0.  It is, therefore, affected by a memory corruption
vulnerability related to the file 'rmsdk_wrapper.dll' and handling
embedded font streams, such as those in PDF files, that could allow
denial of service attacks and possibly arbitrary code execution."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb13-20.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe Digital Editions 2.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:digital_editions");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:'Windows');
  script_copyright(english:'This script is Copyright (C) 2014 Tenable Network Security, Inc.');

  script_dependencies('adobe_digital_editions_installed.nbin');
  script_require_keys('SMB/Adobe_DigitalEditions/installed');
  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');

get_kb_item_or_exit("SMB/Adobe_DigitalEditions/installed");

info =  '';
info2 = '';
vuln = 0;
errors = make_list();
installs = get_kb_list_or_exit('SMB/Adobe_DigitalEditions/*');

foreach key (keys(installs))
{
  ver_ui = NULL;
  if (key == "SMB/Adobe_DigitalEditions/installed") continue;
  if ("Ver_UI" >< key) continue;

  exe = installs[key];
  pieces = split(key, sep:'/', keep:FALSE);
  version = pieces[2];

  if (version == "Unknown")
  {
    errors = make_list(errors, "The version of "+exe+" could not be determined and, therefore, cannot be checked.");
    continue;
  }

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  # See if a Ver_UI exists for this version
  key2 = key - "/Path";
  key2 += "/Ver_UI";
  if (!isnull(installs[key2]))
    ver_ui = installs[key2];

  # Affected as posted by vendor :
  # 2.0.0
  if ((ver[0] == 2 && ver[1] == 0 && ver[2] == 0))
  {
    vuln++;
    info += '\n  Path              : '+exe;

    if (ver_ui)
      info += '\n  Installed version : '+version+' ('+ver_ui+')';
    else
      info += '\n  Installed version : '+version+'';

    info += '\n  Fixed version     : 2.0.1 (2.0.1.78765)\n';
  }
  else
    info2 += " and " + version;
}

if (info)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    if (vuln > 1) s = "s of Adobe Digital Editions are";
    else s = " of Adobe Digital Editions is";

    report =
      '\nThe following vulnerable instance'+s+' installed on the'+
      '\nremote host :\n'+
      info;
    security_hole(port:port, extra:report);
  }
  else security_hole(port);

  exit(0);
}

if (info2)
{
  info2 -= " and ";
  if (" and " >< info2) be = "are";
  else be = "is";

  exit(0, "The host is not affected since Adobe Digital Editions "+info2+" "+be+" installed.");
}
else
{
  # info2 is empty. See if we have error(s) to report first though.
  num_of_errors = max_index(errors);

  if (num_of_errors == 0)
    exit(1, "Unexpected error - 'info2' is empty.");
  else if (num_of_errors == 1)
    exit(1, errors[0]);
  else
    exit(1, 'Errors were encountered verifying installs :\n ' + join(errors, sep:'\n '));
}
