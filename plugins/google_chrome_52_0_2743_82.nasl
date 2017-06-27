#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92628);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/11/11 20:19:26 $");

  script_cve_id(
    "CVE-2016-1705",
    "CVE-2016-1706",
    "CVE-2016-1708",
    "CVE-2016-1709",
    "CVE-2016-1710",
    "CVE-2016-1711",
    "CVE-2016-5127",
    "CVE-2016-5128",
    "CVE-2016-5129",
    "CVE-2016-5130",
    "CVE-2016-5131",
    "CVE-2016-5132",
    "CVE-2016-5133",
    "CVE-2016-5134",
    "CVE-2016-5135",
    "CVE-2016-5136",
    "CVE-2016-5137"
  );
  script_bugtraq_id(92053);
  script_osvdb_id(
    137439,
    137773,
    141924,
    141926,
    141927,
    141928,
    141929,
    141930,
    141931,
    141932,
    141933,
    141934,
    141935,
    141936,
    141937,
    141938,
    141939,
    141940,
    141947,
    141948,
    141949,
    141950,
    141951,
    141952,
    141989,
    141990,
    141991,
    141992,
    141994,
    141995,
    142038,
    142039,
    142040,
    142085,
    141929
  );

  script_name(english:"Google Chrome < 52.0.2743.82 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Google Chrome.");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is
prior to 52.0.2743.82. It is, therefore, affected by multiple
vulnerabilities :

  - Multiple unspecified vulnerabilities exist that allow a
    remote attacker to cause a denial of service condition
    or possibly have other impact via unknown vectors.
    (CVE-2016-1705)

  - A sandbox protection bypass vulnerability exists in
    PPAPI due to a failure to validate the origin of IPC
    messages to the plugin broker process. An
    unauthenticated, remote attacker can exploit this to
    bypass the sandbox. (CVE-2016-1706)

  - A use-after-free error exists in Extensions due to a
    failure to consider object lifetimes during progress
    observation. An unauthenticated, remote attacker can
    exploit this to dereference already freed memory,
    resulting in the execution of arbitrary code.
    (CVE-2016-1708)

  - An array indexing error exists in the ByteArray::Get()
    function in data/byte_array.cc due to improper 
    validation of user-supplied input. An unauthenticated,
    remote attacker can exploit this to cause a heap-based
    buffer overflow, resulting in a denial of service
    condition or the execution of arbitrary code.
    (CVE-2016-1709)

  - A same-origin bypass vulnerability exists in Blink due
    to a failure to prevent window creation by a deferred
    frame. A remote attacker can exploit this to bypass the
    same-origin policy. (CVE-2016-1710)

  - A same-origin bypass vulnerability exists in Blink due
    to a failure to disable frame navigation during a detach
    operation on a DocumentLoader object. A remote attacker
    can exploit this to bypass the same-origin policy.
    (CVE-2016-1711)

  - A use-after-free error exists in Blink in the
    previousLinePosition() function. An unauthenticated,
    remote attacker can exploit this, via crafted JavaScript
    code involving an @import at-rule in a Cascading Style
    Sheets (CSS) token sequence in conjunction with a
    rel=import attribute of a LINK element, to cause a
    denial of service condition or the execution of
    arbitrary code. (CVE-2016-5127)

  - A same-origin bypass vulnerability exists in Google V8
    due to a failure to prevent API interceptors from
    modifying a store target without setting a property. A
    remote attacker can exploit this to bypass the
    same-origin policy. (CVE-2016-5128)

  - A flaw exists in V8 due to improper processing of
    left-trimmed objects. An unauthenticated, remote
    attacker can exploit this, via crafted JavaScript code,
    to cause a denial of service condition or the execution
    of arbitrary code. (CVE-2016-5129)

  - A flaw exists that is triggered when handling two
    forward navigations that compete in different frames. A
    remote attacker can exploit this to conduct a URL
    spoofing attack. (CVE-2016-5130)

  - A use-after-free error exists in libxml2 in the
    xmlXPtrRangeToFunction() function. An unauthenticated,
    remote attacker can exploit this to dereference already
    freed memory, resulting in the execution of arbitrary
    code. (CVE-2016-5131)

  - A same-origin bypass vulnerability exists in the Service
    Workers subsystem due to a failure to properly implement
    the Secure Contexts specification during decisions about
    whether to control a subframe. A remote attacker can
    exploit this to bypass the same-origin policy.
    (CVE-2016-5132)

  - A flaw exists in the handling of origin information
    during proxy authentication that allows a
    man-in-the-middle attacker to spoof a
    proxy-authentication login prompt or trigger incorrect
    credential storage by modifying the client-server data
    stream. (CVE-2016-5133)

  - A validation flaw exists in the Proxy Auto-Config (PAC)
    feature due to a failure to ensure that URL information
    is restricted to a scheme, host, and port. A remote
    attacker can exploit this to disclose credentials by
    operating a server with a PAC script. (CVE-2016-5134)

  - A cross-origin bypass vulnerability exists in Blink due
    to a failure to consider referrer-policy information
    inside an HTML document during a preload request. A
    remote attacker can exploit this to bypass the Content
    Security Policy (CSP) protection mechanism.
    (CVE-2016-5135)

  - A use-after-free error exists in Extensions that allows
    a remote attacker to dereference already freed memory,
    resulting in the execution of arbitrary code with
    elevated privileges. (CVE-2016-5136)

  - An information disclosure vulnerability exists in Blink
    when handling HTTP vs HTTPs ports in source expressions.
    An unauthenticated, remote attacker can exploit this to
    determine whether a specific HTTP Strict Transport
    Security (HSTS) web site has been visited by reading a
    CSP report. (CVE-2016-5137)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # http://googlechromereleases.blogspot.com/2016/07/stable-channel-update.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7c7c32d0");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 52.0.2743.82 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/29");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");
installs = get_kb_list("SMB/Google_Chrome/*");

google_chrome_check_version(installs:installs, fix:'52.0.2743.82', severity:SECURITY_HOLE);
