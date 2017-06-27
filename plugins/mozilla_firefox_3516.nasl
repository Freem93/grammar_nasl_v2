#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51120);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/16 14:12:50 $");

  script_cve_id("CVE-2010-3766", "CVE-2010-3767", "CVE-2010-3768", "CVE-2010-3769", 
                "CVE-2010-3770", "CVE-2010-3771", "CVE-2010-3772", "CVE-2010-3773", 
                "CVE-2010-3774", "CVE-2010-3775", "CVE-2010-3776", "CVE-2010-3778");
  script_bugtraq_id(
    45314,
    45324,
    45326,
    45344,
    45345,
    45346,
    45347,
    45351,
    45352,
    45353,
    45354,
    45355
  );
  script_osvdb_id(
    69768,
    69769,
    69770,
    69771,
    69772,
    69773,
    69774,
    69775,
    69776,
    69777,
    69778,
    69780
  );
  script_xref(name:"Secunia", value:"42517");

  script_name(english:"Firefox < 3.5.16 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Firefox");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Firefox is earlier than 3.5.16.  Such
versions are potentially affected by multiple vulnerabilities :

  - Multiple memory corruption issues could lead to
    arbitrary code execution. (MFSA 2010-74)
  
  - On the Windows platform, when 'document.write()' is 
    called with a very long string, a buffer overflow could
    be triggered. (MFSA 2010-75)

  - A privilege escalation vulnerability exists with
    'window.open' and the '<isindex>' element. 
    (MFSA 2010-76)

  - Arbitrary code execution is possible when using HTML
    tags inside a XUL tree. (MFSA 2010-77)

  - Downloadable fonts could expose vulnerabilities in the
    underlying OS font code. (MFSA 2010-78)

  - A Java security bypass vulnerability exists when 
    LiveConnect is loaded via a 'data:' URL meta refresh. 
    (MFSA 2010-79)

  - A use-after-free error exists with nsDOMAttribute
    MutationObserver. (MFSA 2010-80)

  - An integer overflow exists in NewIdArray. (MFSA 2010-81)

  - It is possible to circumvent the fix for CVE-2010-0179.
    (MFSA 2010-82)
    
  - It is possible to spoof SSL in the location bar using
    the network error page. (MFSA 2010-83)

  - A cross-site scripting hazard exists in multiple
    character encodings. (MFSA 2010-84)");

  # http://lcamtuf.blogspot.com/2010/12/firefox-3613-damn-you-corner-cases.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?de9e67fa");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-74.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-75.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-76.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-77.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-78.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-79.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-80.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-81.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-82.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-83.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-84.html");
  # http://www.mozilla.org/security/known-vulnerabilities/firefox35.html#firefox3.5.16
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?09164c5a");

  script_set_attribute(attribute:"solution", value:"Upgrade to Firefox 3.5.16 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vuln_publication_date", value:"2010/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");
  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport"); 

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'3.5.16', severity:SECURITY_HOLE);