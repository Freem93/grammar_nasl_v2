#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(24268);
  script_version("$Revision: 1.19 $");

  script_cve_id("CVE-2007-0015");
  script_bugtraq_id(21829);
  script_osvdb_id(31023);
  script_xref(name:"CERT", value:"442497");

  script_name(english:"QuickTime RTSP URL Handler Buffer Overflow (Windows)");
  script_summary(english:"Checks version of QuickTime on Windows");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote version of QuickTime is affected by a buffer overflow
vulnerability." );
 script_set_attribute(attribute:"description", value:
"A buffer overflow vulnerability exists in the RTSP URL handler in the
version of QuickTime installed on the remote host.  Using either HTML,
JavaScript or a QTL file as an attack vector and an RTSP URL with a 
long path component, a remote attacker may be able to leverage this 
issue to execute arbitrary code on the remote host subject to the 
user's privileges." );
  # http://applefun.blogspot.com/2007/01/moab-01-01-2007-apple-quicktime-rtsp.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ebb12673" );
 script_set_attribute(attribute:"see_also", value:"http://projects.info-pull.com/moab/MOAB-01-01-2007.html" );
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=304989" );
 script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/Security-announce/2007/Jan/msg00000.html" );
 script_set_attribute(attribute:"see_also", value:"http://secunia.com/blog/7/" );
 script_set_attribute(attribute:"solution", value:
"Apply Apple's Security Update 2007-001, which is available via the
'Apple Software Update' application, installed with the most recent
version of QuickTime or iTunes." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"exploited_by_malware", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Apple QuickTime 7.1.3 RTSP URI Buffer Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/02/02");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/01/01");
 script_cvs_date("$Date: 2016/11/23 20:42:24 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:quicktime");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
 
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("quicktime_installed.nasl");
  script_require_keys("SMB/QuickTime/Version");

  exit(0);
}


include("global_settings.inc");


ver_ui = get_kb_item("SMB/QuickTime/Version_UI");
ver = get_kb_item("SMB/QuickTime/Version");
if (isnull(ver)) exit(0);

iver = split(ver, sep:'.', keep:FALSE);
for (i=0; i<max_index(iver); i++)
  iver[i] = int(iver[i]);

if (
  iver[0] < 7 || 
  (
    iver[0] == 7 && 
    (
      iver[1] < 1 ||
      (
        iver[1] == 1 &&
        (
          iver[2] < 3 ||
          (iver[2] == 3 && iver[3] < 191)
        )
      )
    )
  )
)
{
  if (report_verbosity > 0 && ver_ui)
  {
    report = string(
      "\n",
      "QuickTime ", ver_ui, " is currently installed on the remote host.\n"
    );
    security_warning(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_warning(get_kb_item("SMB/transport"));
}
