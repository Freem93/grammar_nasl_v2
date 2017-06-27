#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(56258);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/17 16:53:08 $");

  script_cve_id(
    "CVE-2011-2426",
    "CVE-2011-2427",
    "CVE-2011-2428",
    "CVE-2011-2429",
    "CVE-2011-2430",
    "CVE-2011-2444"
  );
  script_bugtraq_id(
    49710,
    49714,
    49715,
    49716,
    49717,
    49718
  );
  script_osvdb_id(75625, 75626, 75627, 75628, 75629, 75630);

  script_name(english:"Flash Player for Mac <= 10.3.183.7 Multiple Vulnerabilities (APSB11-26)");
  script_summary(english:"Checks version of Flash Player from Info.plist");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Mac OS X host has a browser plugin that is affected by
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its version, the instance of Flash Player installed on
the remote Mac OS X host is 10.3.183.7 or earlier.  It is therefore
reportedly affected by several critical vulnerabilities :

  - Multiple AVM stack overflow vulnerabilities could lead
    to code execution. (CVE-2011-2426, CVE-2011-2427)

  - A logic error issue could lead to code execution or 
    a browser crash. (CVE-2011-2428)

  - A Flash Player security control bypass vulnerability 
    could lead to information disclosure. (CVE-2011-2429)

  - A streaming media logic error vulnerability could lead
    to code execution. (CVE-2011-2430)

  - A universal cross-site scripting vulnerability could be
    abused to take actions on a user's behalf on any 
    website if the user is tricked into visiting a 
    malicious website. Note that this issue is reportedly
    being actively exploited in targeted attacks. 
    (CVE-2011-2444)"
  );
  # https://github.com/zrong/blog/tree/master/flashplayer_crash_on_netstream_play/project
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ace6f27f");
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.adobe.com/support/security/bulletins/apsb11-26.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to Adobe Flash for Mac version 10.3.183.10 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/09/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_flash_player_installed.nasl");
  script_require_keys("MacOSX/Flash_Player/Version");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


version = get_kb_item_or_exit("MacOSX/Flash_Player/Version");

# nb: we're checking for versions less than *or equal to* the cutoff!
cutoff_version = "10.3.183.7";
fixed_version = "10.3.183.10";

if (ver_compare(ver:version, fix:cutoff_version, strict:FALSE) <= 0)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Installed version : ' + version + 
      '\n  Fixed version     : '+fixed_version+'\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else exit(0, "Flash Player for Mac "+version+" is installed and thus not affected.");
