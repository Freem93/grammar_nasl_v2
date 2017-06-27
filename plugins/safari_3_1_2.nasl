#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(33226);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/14 20:22:11 $");

  script_cve_id(
    "CVE-2008-1573",
    "CVE-2008-2306",
    "CVE-2008-2307",
    "CVE-2008-2540"
  );
  script_bugtraq_id(29445, 29513, 29835, 29836);
  script_osvdb_id(45707, 45892, 46501, 46502, 53623);
  script_xref(name:"Secunia", value:"30775");

  script_name(english:"Safari < 3.1.2 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Safari");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by several
issues." );
 script_set_attribute(attribute:"description", value:
"The version of Safari installed on the remote host reportedly is
affected by several issues :

  - An out-of-bounds memory read while handling BMP and GIF
    images may lead to information disclosure 
    (CVE-2008-1573).

  - Safari will automatically launch executable files
    downloaded from a site if that site is in an IE7 zone
    with 'Launching applications and unsafe files' set to
    'Enable' or an IE6 'Local intranet ' / ' Trusted sites'
    zone (CVE-2008-2306).

  - There is a memory corruption issue in WebKit's
    handling of JavaScript arrays that could be leveraged
    to crash the application or execute arbitrary code
    if visiting a malicious site (CVE-2008-2307).

  - When handling an object with an unrecognized content 
    type, Safari does not prompt the user before 
    downloading the object (aka, the 'carpet-bombing'
    issue). If the download location is the Windows
    Desktop (the default), this could lead to arbitrary
    code execution (CVE-2008-2540)." );
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT1222" );
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2008/Jun/msg00001.html" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to Safari 3.1.2 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119, 264, 399);
  script_set_attribute(attribute:"plugin_publication_date", value: "2008/06/20");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:safari");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("safari_installed.nasl");
  script_require_keys("SMB/Safari/FileVersion");

  exit(0);
}


include("global_settings.inc");


ver = get_kb_item("SMB/Safari/FileVersion");
if (isnull(ver)) exit(0);

iver = split(ver, sep:'.', keep:FALSE);
for (i=0; i<max_index(iver); i++)
  iver[i] = int(iver[i]);

if (
  iver[0] < 3 ||
  (
    iver[0] == 3 &&
    (
      iver[1] < 525 ||
      (iver[1] == 525 && iver[2] < 21)
    )
  )
)
{
  if (report_verbosity)
  {
    prod_ver = get_kb_item("SMB/Safari/ProductVersion");
    if (!isnull(prod_ver)) ver = prod_ver;

    report = string(
      "\n",
      "Safari version ", ver, " is currently installed on the remote host.\n"
    );
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
