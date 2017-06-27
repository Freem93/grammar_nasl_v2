#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56334);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/16 14:12:50 $");

  script_cve_id(
    "CVE-2011-2372", 
    "CVE-2011-2995",
    "CVE-2011-2996",
    "CVE-2011-2998",
    "CVE-2011-2999",
    "CVE-2011-3000"
  );
  script_bugtraq_id(
    49809,
    49810,
    49811,
    49845,
    49848,
    49849
  );
  script_osvdb_id(75834, 75835, 75837, 75838, 75839, 75841);

  script_name(english:"Firefox 3.6.x < 3.6.23 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Firefox");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Firefox 3.6.x is earlier than 3.6.23 and is
affected by the following vulnerabilities:

  - An integer underflow exists when handling a large 
    JavaScript 'RegExp' expression that can allow a 
    potentially exploitable crash. (CVE-2011-2998)

  - If an attacker could trick a user into holding down the
    'Enter' key, via a malicious game, for example, a 
    malicious application or extension could be downloaded 
    and executed. (CVE-2011-2372)

  - Unspecified errors exist that can be exploited to 
    corrupt memory. No additional information is available 
    at this time. (CVE-2011-2995, CVE-2011-2996)

  - There is an error in the implementation of the 
    'window.location' JavaScript object when creating named
    frames. This can be exploited to bypass the same-origin
    policy and potentially conduct cross-site scripting 
    attacks. (CVE-2011-2999)

  - A weakness exists when handling the 'Location' header. 
    This can lead to response splitting attacks when 
    visiting a vulnerable web server. The same fix has been
    applied to the headers 'Content-Length' and 
    'Content-Disposition'. (CVE-2011-3000)");

  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-36.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-37.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-38.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-39.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-40.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Firefox 3.6.23 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/09/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport"); 

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'3.6.23', min:'3.6', severity:SECURITY_HOLE);