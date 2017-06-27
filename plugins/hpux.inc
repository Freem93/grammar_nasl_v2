# -*- Fundamental -*-
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# hpux.inc 
# $Revision: 1.7 $
#


global_var _hpux_report;


#######################################################
# hpux_check_ctx() returns :                          #
#	1 if system is present in the list            #
#	0 if not                                      #
#######################################################

function hpux_check_ctx (ctx, proc) 
{
 local_var os, hw, list, val, elem, pr;

 os = get_kb_item ("Host/HP-UX/version");
 hw = get_kb_item ("Host/HP-UX/hardware");

 if (proc)
 {
   pr = get_kb_item("Host/HP-UX/processor");
   if (pr != proc) return 0;
 }

 list = split(ctx, sep:' ', keep:0);
 foreach elem (list)
 {
  if (":" >< elem)
  {
   val = split (elem, sep:":", keep:0);
   if ((val[0] == hw) && (val[1] == os))
     return 1;
  }
  else
  {
   if (elem == os)
     return 1;
  }
 }

 return 0;
}



function hpux_installed (app)
{
 local_var swlist, installed_app;

 swlist = get_kb_item("Host/HP-UX/swlist");

 if ( strlen(app) )
 {
   installed_app = egrep (pattern:string(app,'[\t ]+'), string:swlist);
   if (installed_app)
   {
      return 1;
   }
 }

 return 0;
}



#######################################################
# hpux_patch_installed() returns :                    #
#	1 if one of the patches is installed          #
#	0 if not                                      #
#######################################################

function hpux_patch_installed(patches) 
{
 local_var list, elem, installed_app;
 
 list = split(patches, sep:' ', keep:0);
 foreach elem (list)
 {
  if ( hpux_installed (app:elem) == 1)
    return 1;
 }

 return 0;
}


#######################################################
# hpux_check_patch() returns :                        #
#	1 if the patch is not installed               #
#	0 if installed or not needed                  #
#######################################################

function hpux_check_patch (app, version, proc)
{
 local_var pr, swlist, installed_app, installed_version;

 if (proc)
 {
   pr = get_kb_item("Host/HP-UX/processor");
   if (pr != proc) return 0;
 }


 swlist = get_kb_item ("Host/HP-UX/swlist");
 if ( strlen(app) )
 {
   installed_app = egrep (pattern:string(app,'[\t ]+'), string:swlist);
   if ((installed_app) && !egrep (pattern:"^#.*", string:installed_app))
   {
     installed_version = ereg_replace (pattern:string('[\t ]+', app, '[\t ]+(.*)'), replace:"\1", string:installed_app);
     installed_version = chomp (installed_version);

     if (!isnull (version))
     {
      if (installed_version >< version)
      {
        hpux_report_add(app:app, installed:installed_version);
        return 1;
      }
     }
     else
     {
       hpux_report_add(app:app, installed:installed_version);
       return 1;
     }
   }
 }
 
 return 0;
}

#######################################################
# hpux_check_version() returns :                      #
#       1 if the patch is not installed               #
#       0 if installed or not needed                  #
#                                                     #
#  possible values for "func" are <, >, =, <=, >=     #
#######################################################

function hpux_check_version (app, version, proc, func)
{
 local_var pr, swlist, installed_app, installed_version, result, flag;

 if (proc)
 {
   pr = get_kb_item("Host/HP-UX/processor");
   if (pr != proc) return 0;
 }


 swlist = get_kb_item ("Host/HP-UX/swlist");
 if ( strlen(app) )
 {
   installed_app = egrep (pattern:string(app,'[\t ]+'), string:swlist);
   if ((installed_app) && !egrep (pattern:"^#.*", string:installed_app))
   {
     installed_version = ereg_replace (pattern:string('[\t ]+', app, '[\t ]+(.*)'), replace:"\1", string:installed_app);
     installed_version = chomp (installed_version);

     if (!isnull (version))
     {
       result = hpux_compare_ver(a:installed_version, b:version);
       flag = 0;
       if ((func == "<")  && (result == 1  )) flag = 1;
       if ((func == ">")  && (result == -1 )) flag = 1;
       if ((func == "=")  && (result == 0  )) flag = 1;
       if ((func == "<=") && (result != -1 )) flag = 1;
       if ((func == ">=") && (result != 1  )) flag = 1;

       if (flag)
       {
         hpux_report_add(app:app, installed:installed_version);
         return 1;
       }
     }
     else
     {
       hpux_report_add(app:app, installed:installed_version);
       return 1;
     }
   }
 }

 return 0;
}

#######################################
# hpux_compare_ver(a, b) returns :    #
#        1 if a < b                   #
#        0 if a = b                   #
#       -1 if a > b                   #
#######################################
function hpux_compare_ver (a, b)
{
  local_var array_a, array_b, max, ea, eb, i;

   # return true if the two strings are equal
  if (a==b) return 0;

  # split a and b on "."
  array_a = split(tolower(a), sep:".", keep:0);
  array_b = split(tolower(b), sep:".", keep:0);

  # determine which of array_a and array_b have the most elements
  if ( max_index(array_b) < max_index(array_a))
    max = max_index(array_a);
  else
    max = max_index(array_b);

  # loop over all elements of the versions
  for ( i = 0 ; i < max ; i ++ )
  {
    # get the next element of array_a
    if ( max_index(array_a) <= i ) ea = 0;
    else ea = array_a[i];
    if (!ea) ea = 0;

    # get the next element of array_b
    if ( max_index(array_b) <= i ) eb = 0;
    else eb = array_b[i];
    if (!eb) eb = 0;

    #if (ea = eb then next, if ea and eb are all 0's then next
    if (ea!=eb)
    {
      if ( (ea =~ "^\d+$") && (eb =~ "^\d+$") )
      {
        # compare as numbers
        if (int(ea) < int(eb)) return 1;
        if (int(ea) > int(eb)) return -1;
      }
      else
      {
        # compare as strings
        if (ea < eb) return 1;
        if (ea > eb) return -1;
      }
    }
  }

  # if we got to here then the two strings are == , but we should never get to here
  return 0;
}

function hpux_report_add(app, installed)
{
  _hpux_report += '  - Fileset           : ' + app + '\n' +
                  '    Installed version : ' + installed + '\n' +
                  '\n';
}

function hpux_report_get()
{
  if (strlen(_hpux_report)) return '\n' + _hpux_report;
  else return NULL;
}
