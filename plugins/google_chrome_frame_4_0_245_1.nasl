#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42895);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/10/13 15:19:32 $");

  script_bugtraq_id(37067);
  script_osvdb_id(63315);

  script_name(english:"Google Chrome Frame < 4.0.245.1");
  script_summary(english:"Checks version number of Google Chrome Frame");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host contains a web browser plug-in that may allow bypassing
cross-origin protections."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Google Chrome Frame installed on the remote host is
earlier than 4.0.245.1.  Such versions are affected by a vulnerability
that may allow an attacker to bypass cross-origin protections."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3f3e794e");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ddded4cb");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome Frame 4.0.245.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/11/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_frame_installed.nasl");
  script_require_keys("SMB/Google_Chrome_Frame/Installed");

  exit(0);
}


include("global_settings.inc");


# Check each installation.
installs = get_kb_list("SMB/Google_Chrome_Frame/*");
if (isnull(installs)) exit(1, "The 'SMB/Google_Chrome_Frame' KB items are missing.");

info = "";
vulns = make_array();

foreach install(sort(keys(installs)))
{
  if ("/Installed" >< install) continue;

  version = install - "SMB/Google_Chrome_Frame/";
  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  if (
    ver[0] < 4 ||
    (
      ver[0] == 4 && ver[1] == 0 &&
      (
        ver[2] < 245 ||
        (ver[2] == 245 && ver[3] < 1)
      )
    )
  )
    vulns[version] =  installs[install];
}

# Report if vulnerable installs were found.
if (max_index(keys(vulns)))
{
  port = get_kb_item("SMB/transport");

  if (report_verbosity > 0)
  {
    info = "";
    n = 0;
    foreach version (sort(keys(vulns)))
    {
      path = vulns[version];
      if(!isnull(path))
      {
        info += '  ' + version + ', installed under :\n';
        info += '    - ' + path + '\n';
        n++;
      }
    }
    info += '\n';

    if (n > 1) s = "s of Google Chrome Frame are";
    else s = " of Google Chrome Frame is";

    report =
      '\n' +
      "The following vulnerable instance" + s + " installed on" + '\n' +
      "the remote host :" + '\n\n' +
      info;

    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else
{
  if (thorough_tests) exit(0,"No vulnerable versions of Google Chrome Frame were found.");
  else exit(1, "Some installs may have been missed because the 'Perform thorough tests' setting was not enabled.");
}
