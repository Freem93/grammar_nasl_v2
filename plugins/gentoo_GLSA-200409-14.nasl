# @DEPRECATED@
#
# This script has been deprecated and is no longer used as the
# Gentoo advisory says the issue has no security impact.
#
# Disabled on 2011/05/27. 
#
# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200409-14.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2004 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description)
{
 script_id(14695);
 script_version("$Revision: 1.6 $");

 script_cve_id("CVE-2004-0829");
 script_bugtraq_id(11055);
 script_xref(name: "GLSA", value: "200409-14");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200409-14 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in
GLSA-200409-14 (Samba: Remote printing vulnerability)

    Due to a bug in the printer_notify_info() function, authorized users could
    potentially crash the Samba server by sending improperly handled print
    change notification requests in an invalid order. Windows XP SP2 clients
    can trigger this behavior by sending a FindNextPrintChangeNotify() request
    before previously sending a FindFirstPrintChangeNotify() request.
  
Impact

    A remote authorized user could potentially crash a Samba server after
    issuing these out of sequence requests.
  
Workaround

    There is no known workaround at this time.');
script_set_attribute(attribute: 'see_also', value: 'http://samba.org/samba/history/samba-3.0.6.html');
script_set_attribute(attribute: 'see_also', value: 'http://www.securityfocus.com/archive/1/373619');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200409-14.xml');

script_set_attribute(attribute:'solution', value: '    All Samba users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=net-fs/samba-3.0.6"
    # emerge ">=net-fs/samba-3.0.6"');
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/09");
 script_cvs_date("$Date: 2011/05/28 03:38:48 $");
script_end_attributes();

 script_copyright(english: "This script is Copyright (C) 2004-2010 Tenable Network Security, Inc.");
 script_name(english: "[GLSA-200409-14] Samba: Remote printing vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Samba: Remote printing vulnerability');
 exit(0);
}

exit(0);
include('qpkg.inc');
if (qpkg_check(package: "net-fs/samba", unaffected: make_list("ge 3.0.6"), vulnerable: make_list("lt 3.0.6")
)) { security_warning(0); exit(0); }
