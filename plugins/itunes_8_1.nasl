#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(35913);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2009-0016", "CVE-2009-0143");
  script_bugtraq_id(34094);
  script_osvdb_id(52578, 52579);

  script_name(english:"Apple iTunes < 8.1 Multiple Vulnerabilities (credentialed check)");
  script_summary(english:"Checks version of iTunes on Windows");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
multiple vulnerabilities." );
  script_set_attribute(attribute:"description", value:
"The version of Apple iTunes installed on the remote Windows host is
older than 8.1. Such versions may be affected by multiple
vulnerabilities :
  
  - It may be possible to cause a denial of service by
    sending a maliciously crafted DAAP header to the
    application. (CVE-2009-0016)

  - When subscribing to a podcast an authentication dialog
    may be presented without clarifying the origin of the
    authentication request. An attacker could exploit this
    flaw in order to steal the user's iTunes credentials.
    (CVE-2009-0143)" );

  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT3487" );
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2009/Mar/msg00001.html");

  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple iTunes 8.1 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 200);

 script_set_attribute(attribute:"plugin_publication_date", value: "2009/03/13");
 script_cvs_date("$Date: 2016/11/23 20:31:32 $");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
  script_dependencies("itunes_detect.nasl");
  script_require_keys("SMB/iTunes/Version");

  exit(0);
}

include ("global_settings.inc");

version = get_kb_item("SMB/iTunes/Version");
if (isnull(version)) exit(0);

ver = split(version, sep:'.', keep:FALSE);
for(i=0;i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if(
  ver[0] < 8 ||
  (
    ver[0] == 8 &&
    (
      ver[1] <1 ||
      (
        ver[1]==1 && ver[2]==0 && ver[3] < 51
      )
    )
  )
)
{
  if (report_verbosity)
  {
    report = string(
      "\n",
      "iTunes ", version, " is installed on the remote host.\n"
    );
    security_warning(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_warning(get_kb_item("SMB/transport"));
}
