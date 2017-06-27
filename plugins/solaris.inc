###
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# solaris.inc
# $Revision: 1.16 $
###

##
# Value for storing error report
##
global_var report;
##
# Value for storing supplemental information for error report
##
global_var details;
report = NULL;
details = NULL;

##
# Retrieves internal 'report' value, adds 'details' value if exists,
#              labels as packages.
#
# @anonparam First string to add 
#
# @return internal 'report' value, with a list of affected packages
#             if applicable
##
function solaris_get_report()
{
 local_var ret;

 ret = report;
 if ( strlen(details) )
   ret += '\nList of affected packages :\n' + details;

 return ret;
}

##
# Retrieves internal 'report' value, adds 'details' value if exists,
#              does not label as packages, used for Solaris 11+.
#
# @anonparam First string to add 
#
# @return internal 'report' value, with details if applicable. 
##
function solaris_get_report2()
{
 local_var ret;

 ret = report;
 if ( strlen(details) )
   ret += '\n' + details;

 return ret;
}

##
# Adds anonymous argument string to internal 'report' value 
#
# @anonparam First string to add 
##
function solaris_report_set()
{
 report = _FCT_ANON_ARGS[0] + '\n';
}

##
# Adds anonymous argument string to internal 'details' value 
#
# @anonparam First string to add 
##
function solaris_details_add()
{
 details += _FCT_ANON_ARGS[0] + '\n';
}

##
# Compares two version strings, returns difference between first piece
#              before . on each.
#
# @anonparam First first package version
# @anonparam Second second package version
#
# @remark Example version: 11.10.13.52
#
# @return <0 if second argument first part is higher version or
#         >0 if first argument first part is higher version or
#         0 if arguments first parts equal 
##
function maj_vers_cmp()
{
 local_var a, b, i;
 local_var m;

 a = _FCT_ANON_ARGS[0];
 b = _FCT_ANON_ARGS[1];
 a = split(a, sep:".", keep:FALSE);
 b = split(b, sep:".", keep:FALSE);
 return int(a[0]) - int(b[0]);
}

##
# Compares two version strings
#
#
# @anonparam First first package version
# @anonparam Second second package version
#
# @remark Example version: 11.10.13.52
#
# @return <0 if second argument is higher version or
#              second contains all of first but has higher max_index
#         >0 if first argument is higher version or
#              first contains all of second but has higher max_index
#         0 if arguments equal 
##
function vers_cmp()
{
 local_var a, b, i;
 local_var m;

 a = _FCT_ANON_ARGS[0];
 b = _FCT_ANON_ARGS[1];
 a = split(a, sep:".", keep:FALSE);
 b = split(b, sep:".", keep:FALSE);
 m = max_index(a);
 if ( max_index(b) < m ) m = max_index(b);

 for ( i = 0 ; i < m; i ++ )
 {
  if ( a[i] != b[i] )
	return int(a[i]) - int(b[i]);
 }

 
 return max_index(a) - max_index(b);
}

##
# Compares two Solaris 10 (or below) package versions
#
#
# @anonparam First first package version
# @anonparam Second second package version
#
# @remark Example version: 3.6,REV=2004.11.10.13.52
#
# @return -1 if second argument is higher version or
#              less than two arguments passed
#         1 if first argument is higher version or
#              post-REV revision year mismatch
#         0 if arguments equal version or
#              pre-REV major version (all digits) mismatch or
##
function sol_vers_cmp()
{
 local_var a, b, i;
 local_var n, t;
 local_var a_maj, b_maj, a_min, b_min;

 a = _FCT_ANON_ARGS[0];
 b = _FCT_ANON_ARGS[1];
 if ( isnull(a) || isnull(b) ) return -1;

 if ( "," >< a   )
 {
   t = split(a, sep:',', keep:FALSE);
   a_maj = t[0]; 
   a_min = t[1];
 }
 else a_maj = a;

 if ( "," >< b  )
 {
   t = split(b, sep:',', keep:FALSE);
   b_maj = t[0]; 
   b_min = t[1];
 }
 else b_maj = b;

 #
 # If the major version is not the same
 # do not do anything
 #
 n = vers_cmp(a_maj, b_maj);
 if ( n != 0 ) return 1;


 if ( isnull(a_min) )
	{	
	 if ( isnull(b_min) ) return 0;
	 else return 1;	# b is newer
	}

 if ( isnull(b_min) ) 
	return -1; # a is newer

 if ( a_min =~ "REV=" && b_min =~ "REV=" )
 {
   a = str_replace(find:"REV=", replace:"", string:a_min);
   b = str_replace(find:"REV=", replace:"", string:b_min);
   if ( maj_vers_cmp(a,b) != 0 ) return 1;
   n = vers_cmp(a,b);
   return n;
 }
 else if ( a_min =~ "PATCH=" && b_min =~ "PATCH=" )
 {
   a = str_replace(find:"PATCH=", replace:"", string:a_min);
   b = str_replace(find:"PATCH=", replace:"", string:b_min);
   n = vers_cmp(a,b);
   return n;
 }
 else return 0; # ????????????
}

##
# Checks the showrev results to see if a patch number is installed
#
#
# @param showrev copy of system's Host/Solaris/showrev kb item 
# @param patch patch number to look for
#
# @return 1 if patch installed for any revision
#         0 if patch not installed for any revision
##
function patch_installed(showrev, patch)
{
 local_var v, p,r,patches,spatches, flag;
 v = split(patch, sep:"-", keep:0);
 patches = egrep(pattern:"^Patch: " + v[0], string:showrev);
 if ( ! patches ) return 0; # No patch
#
# there may be more then one patch version be listed, so split up the result
# and do a foreach check.
#
 spatches = split(patches, keep:0); 
 flag = 0;
 foreach r (spatches)
	{
 	# Get the revision number of the installed patch
 	r = ereg_replace(pattern:"Patch: ([0-9]*-[0-9]*) .*", replace:"\1", string:r);
 	p = split(r, sep:"-", keep:0);
 	# If the installed patch is newer than or equal to what we expect, consider
 	# it installed
 
 	if  ( int(p[1]) >= int(v[1]) ) 
	flag = 1; # Patch is installed
	}
return flag;	
}

##
# Checks the showrev results to see if a patch number is installed,
#              and returns the highest installed revision number of it.
#
#
# @param showrev copy of system's Host/Solaris/showrev kb item 
# @param patch patch number to look for
#
# @return maximum revision number found for this patch if patch installed or
#         NULL if patch not installed for any revision
##
function patch_release_number(showrev, patch)
{
 local_var p, installed;
 local_var line, p2;
 local_var max, imax;
 p = split(patch, sep:'-');
 max = 0;
 installed = egrep(pattern:"^Patch: " + p[0], string:showrev);
 if ( installed )
 {
  foreach line ( split(installed) )
  {
   p = ereg_replace(pattern:"^Patch: ([0-9-]*) .*", string:line, replace:"\1");
   p2 = ereg_replace(pattern:"[0-9]*-([0-9])", string:p, replace:"\1");
   if ( int(p2) > imax ) { imax = int(p2); max = p; }
  }
  return chomp(max);
 }
 else return NULL;
}

##
# If the package version on system is lower or equal than the provided
#              version to check against, checks for patches and obsoleted-by
#              patches on the system.
#
#
# @param release version of Solaris to check against. 5.7 for 7, 5.10 for 10, etc.
# @param arch optional architecture to ensure system application architecture
#              is before running checks
# @param package optional package to check against
# @param patch patch number to check for if package's version is lower/equal
#              than supplied
# @param obsoleted_by optional additional patch numbers to check for if package's
#              version is lower/equal than supplied
# @param version optional version of package to check against
# 
#
# @return 0 if patch installed or
#              any obsoleted_by patch installed or
#              arch mismatch or
#              release mismatch or
#              package not installed or
#              package installed but greater than version
#         -1 if package less than or equal to version installed on system
#              and patch and obsoleted_by patches not installed
##
function solaris_check_patch(release, arch, patch, package, obsoleted_by, version) 
{
 local_var showrev, r, flag, packages, obs, p;

 if ( "_x86" >< release )
	release -= "_x86";

 showrev = get_kb_item("Host/Solaris/showrev");
 if (  ! showrev || !release || !patch ) return 0;

 # Look if at least one of the packages installed are affected
 # by this patch
 flag = 0;
 if ( strlen(package) )
 {
  packages = split(package, sep:" ", keep:FALSE);
  foreach p (packages)
	{
  	if ( get_kb_item("Solaris/Packages/Versions/" + p ) ) flag ++;
	}

 } else flag = 1;

 # No package is affected  - return
 if ( flag == 0 ) return 0;

 r = split(release, sep:" ", keep:0);
 flag = 0;
 foreach release (r)
 {
 if ( egrep(pattern:"^Release: " + release, string:showrev) ) flag ++;
 }

 if ( ! flag ) return 0; # Not the right release

 if ( ! egrep(pattern:"^Application architecture: " + arch, string:showrev) ) 
	return 0; # Wrong architecture (intel vs. sparc)

 if ( patch_installed(patch:patch, showrev:showrev) )
	return 0; # Installed

 if ( obsoleted_by )
 {
  obs = split(obsoleted_by, sep:" ", keep:FALSE);
  foreach p ( obs )
  {
    if ( patch_installed(patch:p, showrev:showrev) || "OBSOLETE" >< p ) 
	return 0; # Installed
  }
 }

 if ( ! isnull(version) )
 {
  if ( sol_vers_cmp(get_kb_item("Solaris/Packages/Versions/" + package), version) > 0 ) return 0; # Installed
 }

 r = NULL;
 r = 'Missing patch : ' + patch;
 if ( patch_release_number(showrev:showrev, patch:patch) )
  r += ' (Current revision : ' + patch_release_number(showrev:showrev, patch:patch) + ')';
 else 
  r += ' (No previous revision of this patch has been installed)';


 if ( strlen(obsoleted_by) )
  r += '\n (This patch has been obsoleted by ' + obsoleted_by + ' which is not installed)\n';

 solaris_report_set(r);
 
 r = '- ' + package + ', version : ' + get_kb_item("Solaris/Packages/Versions/" + package);
 
 solaris_details_add(r);

 return -1; # Not installed
}

##
# Checks if the "entire" package on system is greater than the provided
#              version to check against.
#
#
# @param release specific release string to check the system against
# @param sru text descriptor of Solaris Repository Update number, used
#              in case release on system is lower in warning message
#
# @remark Example Line: 0.5.11-0.175.0.10.1.0.0
# @remark Should check results being > 0.
#
# @return 1 if release on system is below the checked release
#         0 if release on system is above or equal the checked release
#              or if there is a version mismatch (11 Express to 11.1 for example)
#         -1 if incorrect amount of fields in version lines
##
function solaris_check_release(release, sru) 
{
  local_var localrel,a,locala,b,localb,i,m;
  localrel = get_kb_item("Host/Solaris11/release");
  if ( !localrel || !release ) return 0;
  a = split(release, sep:"-", keep:FALSE);
  locala = split(localrel, sep:"-", keep:FALSE);
  if (locala[0] != a[0]) return 0;
  b = split(a[1], sep:".", keep:FALSE);
  localb = split(locala[1], sep:".", keep:FALSE);
  if (max_index(b) != 7) return -1;
  if (max_index(localb) != 7) return -1;
  # First 2 numbers past the dash must be same or it's an OS mismatch
  for (i=0; i<=1; i++)
  {
    if (b[i] != localb[i]) return 0;
  }
  for (i=2;i<=6; i++)
  {
    if (int(b[i]) > int(localb[i])) 
    {
      m = '';
      if (sru)
        m += 'Missing SRU : ' + sru + '\n';
      else
        m += 'Missing a necessary SRU :\n';
      m += 'Local version : ' + localrel + '\n';
      m += 'Fixed version : ' + release + '\n';
      solaris_report_set(m);
      return 1;
    }
    if (int(b[i]) < int(localb[i])) 
    {
      break;
    }
  }
  return 0;
}

##
# Combs through the Host/Solaris11/pkg-list for the package names
#              without the preceeding hierarchy
#
#
# @remark The pkg-list format appears as
#              "compress/gzip                1.3.5-0.175.0.0.0.2.537"
#
# @return list-of package names from Host/Solaris11/pkg-list without
#              category/ancestry hierarchy
#         NULL if KB item Host/Solaris11/pkg-list unavailable/invalid
##
function solaris_pkg_list_leaves()
{
   local_var pkg_list, entries, entry, fullpackage, i, spacesplit, slashsplit, leaf_list;
   pkg_list = get_kb_item("Host/Solaris11/pkg-list");
   if ( !pkg_list) return NULL;
   leaf_list = make_list();
   # Split by newlines
   entries = split(pkg_list, sep:'\n', keep:FALSE);
   # index 0 is the header
   # If there's no more than the header, we have an invalid pkg-list
   if (max_index(entries) < 2) return NULL;
   for ( i = 1 ; i < max_index(entries); i ++ )
   {
     entry = entries[i];
     # Try to skip processing any obviously broken entries
     # (shouldn't be any)
     if (" " >< entry && "/" >< entry)
     {
       spacesplit = split(entry, sep:' ', keep:FALSE);
       # First split by spaces, first entry is the package
       fullpackage = spacesplit[0];
       # Split by slashes, last part is the leaf package name
       slashsplit = split(fullpackage, sep:"/", keep:FALSE);
       # Push that
       leaf_list[max_index(leaf_list)] = slashsplit[max_index(slashsplit) - 1];
     }
   }
   if (empty_or_null(leaf_list)) return NULL;
   return join(sep:'\n',sort(leaf_list));
}
