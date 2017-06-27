#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58073);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/09/17 11:05:42 $");

  script_cve_id("CVE-2011-3026");
  script_bugtraq_id(52049);
  script_osvdb_id(79294);

  script_name(english:"Thunderbird 3.1.x < 3.1.19 png_decompress_chunk Integer Overflow (Mac OS X)");
  script_summary(english:"Checks version of Thunderbird");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains an email client that is potentially
affected by an integer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:

"The installed version of Thunderbird 3.1.x is earlier than 3.1.19 and
is, therefore, potentially affected by an integer overflow
vulnerability in libpng, a library used by this application.  When
decompressing certain PNG image files, this could be exploited to
crash the application or even execute arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-11.html");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6846f277");
  script_set_attribute(attribute:"solution", value:"Upgrade to Thunderbird 3.1.19 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/02/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("macosx_thunderbird_installed.nasl");
  script_require_keys("MacOSX/Thunderbird/Installed");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


kb_base = "MacOSX/Thunderbird";
get_kb_item_or_exit(kb_base+"/Installed");
version = get_kb_item_or_exit(kb_base+"/Version", exit_code:TRUE);

ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);
# nb: make sure we have at least 3 parts for the check.
for (i=max_index(ver); i<3; i++)
  ver[i] = 0;

if (ver[0] == 3 && ver[1] == 1 && ver[2] < 19)
{
  if (report_verbosity > 0)
  {
    info +=
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 3.1.19' + '\n';
    security_hole(port:0, extra:info);
  }
  else security_hole(0);
  exit(0);
}
else 
{
  if (ver[0] == 3 && ver[1] == 1) exit(0, "The Thunderbird "+version+" install is not affected.");
  else exit(0, "Thunderbird 3.1.x is not installed.");
}
