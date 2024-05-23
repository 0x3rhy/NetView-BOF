from havoc import Demon, RegisterCommand, RegisterModule

def netview_bof( demonID, *params ):
    TaskID : str    = None
    demon  : Demon  = None
    #packer = Packer()
    demon  = Demon( demonID )

    TaskID = demon.ConsoleWrite( demon.CONSOLE_TASK, f"Tasked demon to run NetView" )

    demon.InlineExecute( TaskID, "go", f"netview.{demon.ProcessArch}.o", b'', False )

    return TaskID

RegisterCommand(netview_bof, "", "netview_bof", "lists all servers of the specified type that are visible in a domain.", 0, "usage itself: netview_bof", "" )