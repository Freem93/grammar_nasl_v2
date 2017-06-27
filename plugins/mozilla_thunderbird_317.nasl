#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51123);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2014/09/18 10:39:01 $");

  script_cve_id("CVE-2010-3768", "CVE-2010-3769", "CVE-2010-3776", "CVE-2010-3777", 
                "CVE-2010-3778");
  script_bugtraq_id(45344, 45345, 45347, 45348, 45352);
  script_osvdb_id(69770, 69771, 69778, 69779, 69780);

  script_name(english:"Mozilla Thunderbird 3.1.x < 3.1.7 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Thunderbird");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a mail client that is affected by 
multiple vulnerabilities.");
  
  script_set_attribute(attribute:"description", value:
"The installed version of Thunderbird is earlier than 3.1.x < 3.1.7.
Such versions are potentially affected by multiple vulnerabilities :

  - Multiple memory corruption issues could lead to
    arbitrary code execution.(MFSA 2010-74)
  
  - On the Windows platform, when 'document.write()' is 
    called with a very long string, a buffer overflow could
    be triggered. (MFSA 2010-75)

  - Downloadable fonts could expose vulnerabilities in the
    underlying OS font code. (MFSA 2010-78)");

  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-74.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-75.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-78.html");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2dec7d97");

  script_set_attribute(attribute:"solution", value:"Upgrade to Thunderbird 3.1.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vuln_publication_date", value:"2010/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/10");
  script_set_attribute(attribute:"plugin_type", value:"local");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");
  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport");

installs = get_kb_list("SMB/Mozilla/Thunderbird/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Thunderbird");

mozilla_check_version(installs:installs, product:'thunderbird', esr:FALSE, fix:'3.1.7', min:'3.1.0', severity:SECURITY_HOLE);