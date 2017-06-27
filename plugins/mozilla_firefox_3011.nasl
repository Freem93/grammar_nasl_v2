#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(39372);
  script_version("$Revision: 1.19 $");

  script_cve_id(
    "CVE-2009-1392", 
    "CVE-2009-1832", 
    "CVE-2009-1833", 
    "CVE-2009-1834", 
    "CVE-2009-1835", 
    "CVE-2009-1836", 
    "CVE-2009-1837", 
    "CVE-2009-1838", 
    "CVE-2009-1839", 
    "CVE-2009-1840",
    "CVE-2009-1841"
  );
  script_bugtraq_id(
    35360, 
    35370, 
    35371, 
    35372, 
    35373, 
    35377, 
    35380, 
    35383, 
    35386, 
    35388, 
    35391
  );
  script_osvdb_id(
    55138,
    55139,
    55140,
    55141,
    55142,
    55143,
    55144,
    55145,
    55146,
    55147,
    55148,
    55152,
    55153,
    55154,
    55155,
    55157,
    55158,
    55159,
    55160,
    55161,
    55162,
    55163,
    55164
  );
  script_xref(name:"Secunia", value:"35331");
  # BID 35326          -- it's been retired

  script_name(english:"Firefox < 3.0.11 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Firefox");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The installed version of Firefox is earlier than 3.0.11. Such versions
are potentially affected by the following security issues :

  - Multiple memory corruption vulnerabilities could 
    potentially be exploited to execute arbitrary code. 
    (MFSA 2009-24)

  - Certain invalid Unicode characters, when used as a part
    of IDN, can be displayed as a whitespace in the location
    bar. An attacker could exploit this vulnerability to
    spoof the location bar. (MFSA 2009-25)  

  - It may be possible for local resources loaded via
    'file:' protocol to access any domain's cookies saved
    on a user's system. (MFSA 2009-26)

  - It may be possible to tamper with SSL data via non-200
    responses to proxy CONNECT requests. (MFSA 2009-27)

  - A race condition exists in 'NPObjWrapper_NewResolve' 
    when accessing the properties of a NPObject, a 
    wrapped JSObject. This flaw could be potentially
    exploited to execute arbitrary code on the remote
    system. (MFSA 2009-28)

  - If the owner document of an element becomes null after
    garbage collection, then it may be possible to execute
    the event listeners within the wrong JavaScript context.
    An attacker could potentially exploit this vulnerability
    to execute arbitrary JavaScript with chrome privileges.
    (MFSA 2009-29)  

  - When the 'file:' resource is loaded from the location
    bar, the resource inherits the principal of the 
    previously loaded document. This could potentially allow 
    unauthorized access to local files. (MFSA 2009-30)

  - While loading external scripts into XUL documents
    content-loading policies are not checked. 
    (MFSA 2009-31)   

  - It may be possible for scripts from page content to
    run with elevated privileges. (MFSA 2009-32)" 
);

 script_set_attribute(attribute:"see_also", value:"http://research.microsoft.com/apps/pubs/default.aspx?id=79323" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-24.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-25.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-26.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-27.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-28.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-29.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-30.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-31.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-32.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 3.0.11 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(20, 94, 200, 264, 287, 362);

 script_set_attribute(attribute:"plugin_publication_date", value: "2009/06/12");
 script_set_attribute(attribute:"patch_publication_date", value: "2009/06/11");
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

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'3.0.11', severity:SECURITY_HOLE);