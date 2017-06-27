#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35778);
  script_version("$Revision: 1.16 $");

  script_cve_id(
    "CVE-2009-0040",
    "CVE-2009-0771",
    "CVE-2009-0772",
    "CVE-2009-0773",
    "CVE-2009-0774",
    "CVE-2009-0775",
    "CVE-2009-0776",
    "CVE-2009-0777"
  );
  script_bugtraq_id(33990);
  script_osvdb_id(
    52444,
    52445,
    52446,
    52447,
    52448,
    52449,
    52450,
    52451,
    52452,
    53315,
    53316,
    53317
  );

  script_name(english:"Firefox 3.0.x < 3.0.7 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Firefox");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities." );
  script_set_attribute(attribute:"description", value:
"The installed version of Firefox 3.0.x is earlier than 3.0.7. Such 
versions are potentially affected by the following security  issues :

  - By exploiting stability bugs in the browser engine, it 
    might be possible for an attacker to execute arbitrary 
    code on the remote system under certain conditions. 
    (MFSA 2009-07)

  - A vulnerability in Mozilla's garbage collection process
    could be exploited to run arbitrary code on the remote
    system. (MFSA 2009-08)

  - It may be possible for a website to read arbitrary XML
    data from another domain by using nsIRDFService and a 
    cross-domain redirect. (MFSA 2009-09)

  - Vulnerabilities in the PNG libraries used by Mozilla
    could be exploited to execute arbitrary code on the 
    remote system. (MFSA 2009-10)

  - Certain invisible characters are decoded before being
    displayed on the location bar. An attacker may be able
    to exploit this flaw to spoof the location bar and 
    display a link to a malicious URL. (MFSA 2009-11)" );
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-07.html" );
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-08.html" );
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-09.html" );
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-10.html" );
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-11.html" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 3.0.7 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 94, 200, 399);
  script_set_attribute(attribute:"plugin_publication_date", value: "2009/03/05");
  script_set_attribute(attribute:"patch_publication_date", value: "2009/03/04");
 script_cvs_date("$Date: 2016/11/28 21:52:56 $");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");
  exit(0);
}


include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport"); 

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'3.0.7', min:'3.0', severity:SECURITY_HOLE);