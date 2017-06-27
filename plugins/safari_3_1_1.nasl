#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(31993);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/14 20:22:11 $");

  script_cve_id(
    "CVE-2007-2398",
    "CVE-2008-1024",
    "CVE-2008-1025",
    "CVE-2008-1026"
  );
  script_bugtraq_id(24484, 28813, 28814, 28815);
  script_osvdb_id(38862, 43634, 43980, 44468);
  script_xref(name:"Secunia", value:"29846");

  script_name(english:"Safari < 3.1.1 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Safari");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by several
issues." );
 script_set_attribute(attribute:"description", value:
"The version of Safari installed on the remote host reportedly is
affected by several issues :

  - A malicious website can spoof window titles and URL bars
    (CVE-2007-2398).

  - A memory corruption issue in the file downloading
    capability could lead to a crash or arbitrary code
    execution (CVE-2008-1024).

  - A cross-site scripting vulnerability exists in WebKit's
    handling of URLs that contain a colon character in
    the host name (CVE-2008-1025).

  - A heap-based buffer overflow exists in WebKit's handling
    of JavaScript regular expressions (CVE-2008-1026)." );
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT1467" );
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2008/Apr/msg00001.html" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to Safari 3.1.1 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(79, 119, 399);
  script_set_attribute(attribute:"plugin_publication_date", value: "2008/04/18");
  script_set_attribute(attribute:"vuln_publication_date", value: "2007/06/14");
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
      (iver[1] == 525 && iver[2] < 17)
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
