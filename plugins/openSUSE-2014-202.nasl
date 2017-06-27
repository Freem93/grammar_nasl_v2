#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-202.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75286);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:39:49 $");

  script_cve_id("CVE-2014-1695");
  script_bugtraq_id(65844);

  script_name(english:"openSUSE Security Update : otrs (openSUSE-SU-2014:0360-1)");
  script_summary(english:"Check for the openSUSE-2014-202 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The OTRS ticket system was updated to 3.1.20 / 3.2.15 :

On openSUSE 12.3 it was updated to 3.1.20: (fix for OSA-2014-03,
CVE-2014-1695)

  - Improved HTML filter.

  - 3.1.19 2014-01-28

  - Fixed bug#10158 - Missing quoting in
    State::StateGetStatesByType().

  - Fixed bug#10099 - Missing challenge token checks on
    customer interface.

  - Fixed bug#8489 - setting Tickets per page resets
    AgentTicketQueue.

  - Fixed bug#9661 - Useless code in DynamicField backend.

  - Fixed bug#9622 - Actions in Small ticket overview don't
    work when cookies are turned off.

  - Fixed bug#9541 - Package manager cannot use https proxy.

  - Fixed bug#9594 - No auto-reply sent with multiple From
    addresses in AgentTicketPhone on PostgreSQL and Oracle.

  - Fixed bug#3434 - Validity of search time frame not
    checked by OTRS.

  - Fixed bug#9596 - On merge and bounce screens is
    confusing when fill or not 'To', 'Subject' and 'Body'
    fields.

  - Fixed bug#9595 - Incomplete page reload handling in
    merge and bounce.

  - Fixed bug#3007 - CheckMXRecord and CheckEmailAddresses
    have no effect on AgentTicketBounce.

  - Fixed bug#9512 - Database error for invalid date in
    AgentTicketSearch.

  - Fixed bug#8835 - No article found for TicketID <TICKET
    ID> when showing group tickets

  - Fixed bug#9583 - Dynamic Fields of type Date have
    timestamp in notifications.

  - Fixed bug#9579 - SOAP Serializer used in
    Kernel/GenericInterface/Transport/ HTTP/SOAP.pm does not
    correctly set namespace.

  - Fixed bug#7359 - Setting pending states via generic
    agent does not set pending time.

  - Fixed bug#8380 - Middle name not displayed in
    AdminCustomerUser.

  - Fixed bug#9576 - GI TicketSearch Date and Date/Time
    dynamic fields are ignored.

  - Changed Dynamic Field SearchFieldParameterBuild() API,
    LayoutObject is now optional.

  - Fixed bug#9573 - Date and DateTime dynamic fields not
    considered in GenericAgent Jobs.

On openSUSE 13.1 it was updated to 3.2.15: (fix for OSA-2014-03,
CVE-2014-1695)

  - Improved HTML filter.

  - Fixed bug#10207 - DynamicField Search-Function in
    CustomerFrontend is not working.

  - Followup for bug#9011 - New value after value mapping
    can't be 0.

  - Fixed bug#10214 - Value '0' for DynamicsFields prevents
    TicketCreation.

  - Fixed bug#9616 - Too long activities and transitions are
    not displayed correctly.

  - Fixed bug#10212 - My tickets & Company tickets in 3.3.4.

  - Fixed bug#10205 - GenericInterface: Mandatory TimeUnits
    can't be 0.

  - Fixed bug#10196 - Ticket merge action does not notify
    the owner of the existing ticket.

  - Fixed bug#9692 - On PhoneOutbound articles, the FROM
    field shows Customer ID instead Agent ID.

  - Fixed bug#10189 - ProcessManagement: Use article subject
    if no ticket title is set.

  - Fixed bug#9654 - TicketUpdate operation doesn't work
    when authenticated as a customer.

  - Fixed bug#10137 - Generic interface TicketCreate
    operation doesn't work when authenticated as a customer.

  - 3.2.14

  - Fixed bug#10172 - Can't create process tickets with
    disabled richtext.

  - Fixed bug#10121 - QQMails break in OTRS.

  - Fixed bug#10158 - Missing quoting in
    State::StateGetStatesByType().

  - Fixed bug#8969 - FAQ module Language files installation
    fails (Kernel/Language permissions).

  - Fixed bug#9959 - & breaks ExpandCustomerName.

  - Fixed bug#10099 - Missing challenge token checks on
    customer interface.

  - Fixed bug#10103 - ArticleTypeID is always undef in
    AgentTicketCompose.

  - Added functionality to disable access to tickets of
    other customers with the same customer company in
    customer interface.

  - Fixed bug#9650 - Special character in customer id breaks
    Open Tickets in AgentTicketZoom.

  - Fixed bug#9723 - TicketAccountedTime stat does not run
    on Oracle with many tickets

  - Fixed bug#10077 - regular expressions in postmaster
    filter return 1 if no regex match.

  - Fixed bug#10070 - Wrong error message if Transition
    contains no transition actions."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-03/msg00030.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=866476"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected otrs packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:otrs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:otrs-itsm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE12\.3|SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3 / 13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"otrs-3.1.20-26.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"otrs-itsm-3.1.10-26.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"otrs-3.2.15-31.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"otrs-itsm-3.2.9-31.5.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "otrs");
}
