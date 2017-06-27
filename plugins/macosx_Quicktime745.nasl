#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(31736);
  script_version("$Revision: 1.12 $");

  if (NASL_LEVEL >= 3004)
  {
    script_cve_id(
      "CVE-2008-1013", 
      "CVE-2008-1014", 
      "CVE-2008-1015", 
      "CVE-2008-1016", 
      "CVE-2008-1017",
      "CVE-2008-1018", 
      "CVE-2008-1019", 
      "CVE-2008-1020", 
      "CVE-2008-1021", 
      "CVE-2008-1022",
      "CVE-2008-1023"
    );
    script_bugtraq_id(28583);
    script_osvdb_id(
        44002,
        44003,
        44004,
        44005,
        44006,
        44007,
        44008,
        44009,
        44010,
        44011,
        44012
    );
    script_xref(name:"Secunia", value:"29650");
  }

  script_name(english:"QuickTime < 7.4.5 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks version of QuickTime on Mac OS X");

 script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains an application that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The version of QuickTime installed on the remote Mac OS X host is
older than 7.4.5.  Such versions contain several vulnerabilities :

  - Untrusted Java applets may obtain elevated privileges
    (CVE-2008-1013).

  - Downloading a movie file may lead to information 
    disclosure (CVE-2008-1014).

  - Viewing a specially crafted movie file may lead to a
    program crash or arbitrary code execution
    (CVE-2008-1015, CVE-2008-1016, CVE-2008-1017, 
    CVE-2008-1018, CVE-2008-1021, CVE-2008-1022).

  - Opening a specially crafted PICT image file may lead 
    to a program crash or arbitrary code execution
    (CVE-2008-1019, CVE-2008-1020, CVE-2008-1023)." );
 script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT1241" );
 # http://lists.apple.com/archives/security-announce/2008/Apr//msg00000.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c815ff7d" );
 script_set_attribute(attribute:"solution", value:
"Either use QuickTime's Software Update preference to upgrade to the
latest version or manually upgrade to QuickTime 7.4.5 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(20, 94, 119, 200);

 script_set_attribute(attribute:"plugin_publication_date", value: "2008/04/03");
 script_set_attribute(attribute:"patch_publication_date", value: "2008/04/02");
 script_cvs_date("$Date: 2016/11/28 21:06:38 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:quicktime");
script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
  script_dependencies("macosx_Quicktime652.nasl");
  script_require_keys("MacOSX/QuickTime/Version");
  exit(0);
}

#

include("global_settings.inc");


ver = get_kb_item("MacOSX/QuickTime/Version");
if (isnull(ver)) exit(0);

iver = split(ver, sep:'.', keep:FALSE);
for (i=0; i<max_index(iver); i++)
  iver[i] = int(iver[i]);

if (
  iver[0] < 7 || 
  (
    iver[0] == 7 && 
    (
      iver[1] < 4 ||
      (iver[1] == 4 && iver[2] < 5)
    )
  )
)
{
  if (report_verbosity)
  {
    report = string(
      "\n",
      "Version ", ver, " of QuickTime is currently installed\n",
      "on the remote host.\n"
    );
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
