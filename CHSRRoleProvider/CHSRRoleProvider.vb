Imports System.Web.Security
Imports System.Configuration.Provider
Imports System.Collections.Specialized
Imports System
Imports System.Data
Imports System.Configuration
Imports System.Diagnostics
Imports System.Web
Imports System.Globalization
Imports Microsoft.VisualBasic
Imports System.Data.SqlClient

'
'
' This provider works with the following schema for the tables of role data.
' 
' CREATE TABLE Roles
' (
'   Rolename varchar (255) NOT NULL,
'   ApplicationName varchar (255) NOT NULL,
'     CONSTRAINT PKRoles PRIMARY KEY (Rolename, ApplicationName)
' )
'
'CREATE TABLE UsersInRoles
' (
'   Username varchar (255) NOT NULL,
'   Rolename varchar (255) NOT NULL,
'   ApplicationName varchar (255) NOT NULL,
'   ProgramFK INT NOT NULL,
'     CONSTRAINT PKUsersInRoles PRIMARY KEY (Username, Rolename, ApplicationName, ProgramFK)
' )
'
'

Public NotInheritable Class CHSRRoleProvider
    Inherits RoleProvider


    '
    ' Global SqlConnection, generated password length, generic exception message, event log info.
    '

    Private conn As SqlConnection

    Private eventSource As String = "CHSRRoleProvider"
    Private eventLog As String = "Application"
    Private exceptionMessage As String = "An exception occurred. Please check the Event Log."

    Private pConnectionStringSettings As ConnectionStringSettings
    Private connectionString As String


    '
    ' If false, exceptions are Thrown to the caller. If true,
    ' exceptions are written to the event log.
    '

    Private pWriteExceptionsToEventLog As Boolean = False

    Public Property WriteExceptionsToEventLog() As Boolean
        Get
            Return pWriteExceptionsToEventLog
        End Get
        Set(ByVal value As Boolean)
            pWriteExceptionsToEventLog = value
        End Set
    End Property
    '
    ' System.Configuration.Provider.ProviderBase.Initialize Method
    '

    Public Overrides Sub Initialize(ByVal name As String, ByVal config As NameValueCollection)


        '
        ' Initialize values from web.config.
        '

        If config Is Nothing Then _
          Throw New ArgumentNullException("config")

        If name Is Nothing OrElse name.Length = 0 Then _
          name = "CHSRRoleProvider"

        If String.IsNullOrEmpty(config("description")) Then
            config.Remove("description")
            config.Add("description", "Sample ODBC Role provider")
        End If

        ' Initialize the abstract base class.
        MyBase.Initialize(name, config)


        If config("applicationName") Is Nothing OrElse config("applicationName").Trim() = "" Then
            pApplicationName = System.Web.Hosting.HostingEnvironment.ApplicationVirtualPath
        Else
            pApplicationName = config("applicationName")
        End If


        If Not config("writeExceptionsToEventLog") Is Nothing Then
            If config("writeExceptionsToEventLog").ToUpper() = "TRUE" Then
                pWriteExceptionsToEventLog = True
            End If
        End If


        '
        ' Initialize SqlConnection.
        '

        pConnectionStringSettings =
          ConfigurationManager.ConnectionStrings(config("connectionStringName"))

        If pConnectionStringSettings Is Nothing OrElse pConnectionStringSettings.ConnectionString.Trim() = "" Then
            Throw New ProviderException("Connection string cannot be blank.")
        End If

        connectionString = pConnectionStringSettings.ConnectionString
    End Sub

    '
    ' System.Web.Security.RoleProvider properties.
    '    

    Private pApplicationName As String

    Public Overrides Property ApplicationName() As String
        Get
            Return pApplicationName
        End Get
        Set(ByVal value As String)
            pApplicationName = value
        End Set
    End Property


    '
    ' System.Web.Security.RoleProvider methods.
    '

    '
    ' RoleProvider.AddUsersToRoles
    '

    Public Overrides Sub AddUsersToRoles(ByVal usernames As String(), ByVal rolenames As String())

        For Each rolename As String In rolenames
            If Not RoleExists(rolename) Then
                Throw New ProviderException("Role name not found.")
            End If
        Next

        For Each username As String In usernames
            If username.Contains(",") Then
                Throw New ArgumentException("User names cannot contain commas.")
            End If

            For Each rolename As String In rolenames
                If IsUserInRole(username, rolename) Then
                    Throw New ProviderException("User is already in role.")
                End If
            Next
        Next


        Dim conn As SqlConnection = New SqlConnection(connectionString)
        Dim cmd As SqlCommand = New SqlCommand("INSERT INTO UsersInRoles " &
          " (Username, Rolename, ApplicationName) " &
          " Values(@Username, @Rolename, @ApplicationName)", conn)

        Dim userParm As SqlParameter = cmd.Parameters.Add("@Username", SqlDbType.VarChar, 255)
        Dim roleParm As SqlParameter = cmd.Parameters.Add("@Rolename", SqlDbType.VarChar, 255)
        cmd.Parameters.Add("@ApplicationName", SqlDbType.VarChar, 255).Value = ApplicationName

        Dim tran As SqlTransaction = Nothing

        Try
            conn.Open()
            tran = conn.BeginTransaction()
            cmd.Transaction = tran

            For Each username As String In usernames
                For Each rolename As String In rolenames
                    userParm.Value = username
                    roleParm.Value = rolename
                    cmd.ExecuteNonQuery()
                Next
            Next

            tran.Commit()
        Catch e As SqlException
            Try
                tran.Rollback()
            Catch
            End Try


            If WriteExceptionsToEventLog Then
                WriteToEventLog(e, "AddUsersToRoles")
            Else
                Throw e
            End If
        Finally
            conn.Close()
        End Try
    End Sub

    Public Overloads Sub AddUsersToRoles(ByVal usernames As String(), ByVal rolenames As String(), ByVal programfk As Integer, ByVal programsitefk As Integer)

        For Each rolename As String In rolenames
            If Not RoleExists(rolename) Then
                Throw New ProviderException("Role name not found.")
            End If
        Next

        For Each username As String In usernames
            If username.Contains(",") Then
                Throw New ArgumentException("User names cannot contain commas.")
            End If

            For Each rolename As String In rolenames
                If Array.IndexOf(GetRolesForUser(username, programfk), rolename) > -1 Then
                    Throw New ProviderException("User is already in role.")
                End If
            Next
        Next

        Dim conn As SqlConnection = New SqlConnection(connectionString)
        Dim cmd As SqlCommand = New SqlCommand("INSERT INTO UsersInRoles " &
          " (Username, Rolename, ApplicationName, programfk, ProgramSiteFK) " &
          " Values(@Username, @Rolename, @ApplicationName, @ProgramFK, @ProgramSiteFK)", conn)

        Dim userParm As SqlParameter = cmd.Parameters.Add("@Username", SqlDbType.VarChar, 255)
        Dim roleParm As SqlParameter = cmd.Parameters.Add("@Rolename", SqlDbType.VarChar, 255)
        cmd.Parameters.Add("@ApplicationName", SqlDbType.VarChar, 255).Value = ApplicationName
        cmd.Parameters.Add("@ProgramFK", SqlDbType.Int).Value = programfk
        cmd.Parameters.Add("@ProgramSiteFK", SqlDbType.Int).Value = programsitefk

        Dim tran As SqlTransaction = Nothing

        Try
            conn.Open()
            tran = conn.BeginTransaction()
            cmd.Transaction = tran

            For Each username As String In usernames
                For Each rolename As String In rolenames
                    userParm.Value = username
                    roleParm.Value = rolename
                    cmd.ExecuteNonQuery()
                Next
            Next

            tran.Commit()
        Catch e As SqlException
            Try
                tran.Rollback()
            Catch
            End Try


            If WriteExceptionsToEventLog Then
                WriteToEventLog(e, "AddUsersToRoles")
            Else
                Throw e
            End If
        Finally
            conn.Close()
        End Try
    End Sub

    '
    ' RoleProvider.CreateRole
    '

    Public Overrides Sub CreateRole(ByVal rolename As String)

        If rolename.Contains(",") Then
            Throw New ArgumentException("Role names cannot contain commas.")
        End If

        If RoleExists(rolename) Then
            Throw New ProviderException("Role name already exists.")
        End If

        Dim conn As SqlConnection = New SqlConnection(connectionString)
        Dim cmd As SqlCommand = New SqlCommand("INSERT INTO Roles " &
                " (Rolename, ApplicationName) " &
                " Values(@Rolename, @ApplicationName)", conn)

        cmd.Parameters.Add("@Rolename", SqlDbType.VarChar, 255).Value = rolename
        cmd.Parameters.Add("@ApplicationName", SqlDbType.VarChar, 255).Value = ApplicationName

        Try
            conn.Open()

            cmd.ExecuteNonQuery()
        Catch e As SqlException
            If WriteExceptionsToEventLog Then
                WriteToEventLog(e, "CreateRole")
            Else
                Throw e
            End If
        Finally
            conn.Close()
        End Try
    End Sub

    '
    ' RoleProvider.DeleteRole
    '

    Public Overrides Function DeleteRole(ByVal rolename As String, ByVal throwOnPopulatedRole As Boolean) As Boolean

        If Not RoleExists(rolename) Then
            Throw New ProviderException("Role does not exist.")
        End If

        If throwOnPopulatedRole AndAlso GetUsersInRole(rolename).Length > 0 Then
            Throw New ProviderException("Cannot delete a populated role.")
        End If

        Dim conn As SqlConnection = New SqlConnection(connectionString)
        Dim cmd As SqlCommand = New SqlCommand("DELETE FROM Roles " &
                " WHERE Rolename = @Rolename AND ApplicationName = @ApplicationName", conn)

        cmd.Parameters.Add("@Rolename", SqlDbType.VarChar, 255).Value = rolename
        cmd.Parameters.Add("@ApplicationName", SqlDbType.VarChar, 255).Value = ApplicationName


        Dim cmd2 As SqlCommand = New SqlCommand("DELETE FROM UsersInRoles " &
                " WHERE Rolename = @Rolename AND ApplicationName = @ApplicationName", conn)

        cmd2.Parameters.Add("@Rolename", SqlDbType.VarChar, 255).Value = rolename
        cmd2.Parameters.Add("@ApplicationName", SqlDbType.VarChar, 255).Value = ApplicationName

        Dim tran As SqlTransaction = Nothing

        Try
            conn.Open()
            tran = conn.BeginTransaction()
            cmd.Transaction = tran
            cmd2.Transaction = tran

            cmd2.ExecuteNonQuery()
            cmd.ExecuteNonQuery()

            tran.Commit()
        Catch e As SqlException
            Try
                tran.Rollback()
            Catch
            End Try


            If WriteExceptionsToEventLog Then
                WriteToEventLog(e, "DeleteRole")

                Return False
            Else
                Throw e
            End If
        Finally
            conn.Close()
        End Try

        Return True
    End Function

    '
    ' RoleProvider.GetAllRoles
    '

    Public Overrides Function GetAllRoles() As String()
        Dim tmpRoleNames As String = ""

        Dim conn As SqlConnection = New SqlConnection(connectionString)
        Dim cmd As SqlCommand = New SqlCommand("SELECT Rolename FROM Roles " &
                  " WHERE ApplicationName = @ApplicationName", conn)

        cmd.Parameters.Add("@ApplicationName", SqlDbType.VarChar, 255).Value = ApplicationName

        Dim reader As SqlDataReader = Nothing

        Try
            conn.Open()

            reader = cmd.ExecuteReader()

            Do While reader.Read()
                tmpRoleNames &= reader.GetString(0) & ","
            Loop
        Catch e As SqlException
            If WriteExceptionsToEventLog Then
                WriteToEventLog(e, "GetAllRoles")
            Else
                Throw e
            End If
        Finally
            If Not reader Is Nothing Then reader.Close()
            conn.Close()
        End Try

        If tmpRoleNames.Length > 0 Then
            ' Remove trailing comma.
            tmpRoleNames = tmpRoleNames.Substring(0, tmpRoleNames.Length - 1)
            Return tmpRoleNames.Split(CChar(","))
        End If

        Return New String() {}
    End Function

    Public Overloads Function GetAllRoles(ByVal programfk As Integer) As String()
        Dim tmpRoleNames As String = ""

        Dim conn As SqlConnection = New SqlConnection(connectionString)
        Dim cmd As SqlCommand = New SqlCommand("SELECT Rolename FROM Roles " &
                  " WHERE ApplicationName = @ApplicationName " &
                  " AND programfk = @ProgramFK", conn)

        cmd.Parameters.Add("@ApplicationName", SqlDbType.VarChar, 255).Value = ApplicationName
        cmd.Parameters.Add("@ProgramFK", SqlDbType.Int).Value = programfk

        Dim reader As SqlDataReader = Nothing

        Try
            conn.Open()

            reader = cmd.ExecuteReader()

            Do While reader.Read()
                tmpRoleNames &= reader.GetString(0) & ","
            Loop
        Catch e As SqlException
            If WriteExceptionsToEventLog Then
                WriteToEventLog(e, "GetAllRoles")
            Else
                Throw e
            End If
        Finally
            If Not reader Is Nothing Then reader.Close()
            conn.Close()
        End Try

        If tmpRoleNames.Length > 0 Then
            ' Remove trailing comma.
            tmpRoleNames = tmpRoleNames.Substring(0, tmpRoleNames.Length - 1)
            Return tmpRoleNames.Split(CChar(","))
        End If

        Return New String() {}
    End Function

    '
    ' RoleProvider.GetRolesForUser
    '

    Public Overrides Function GetRolesForUser(ByVal username As String) As String()
        Dim tmpRoleNames As String = ""

        Dim conn As SqlConnection = New SqlConnection(connectionString)
        'Dim cmd As SqlCommand = New SqlCommand("SELECT Rolename " & _
        '                                       " FROM UsersInRoles " & _
        '                                       " INNER JOIN Users " & _
        '                                       " ON Users.UserName = UsersInRoles.UserName " & _
        '                                       " AND Program = ProgramFK " & _
        '                                       " AND Role = Rolename " & _
        '                                       " WHERE UsersInRoles.Username = @Username " & _
        '                                       " AND UsersInRoles.ApplicationName = @ApplicationName", conn)

        Dim cmd As SqlCommand = New SqlCommand("SELECT Rolename " &
                                               " FROM UsersInRoles " &
                                               " INNER JOIN Users " &
                                               " ON Users.UserName = UsersInRoles.UserName " &
                                               " AND Users.ProgramSite = UsersInRoles.ProgramSiteFK " &
                                               " AND Role = Rolename " &
                                               " WHERE UsersInRoles.Username = @Username " &
                                               " AND UsersInRoles.ApplicationName = @ApplicationName", conn)

        cmd.Parameters.Add("@Username", SqlDbType.VarChar, 255).Value = username
        cmd.Parameters.Add("@ApplicationName", SqlDbType.VarChar, 255).Value = ApplicationName

        Dim reader As SqlDataReader = Nothing

        Try
            conn.Open()

            reader = cmd.ExecuteReader()

            Do While reader.Read()
                tmpRoleNames &= reader.GetString(0) & ","
            Loop
        Catch e As SqlException
            If WriteExceptionsToEventLog Then
                WriteToEventLog(e, "GetRolesForUser")
            Else
                Throw e
            End If
        Finally
            If Not reader Is Nothing Then reader.Close()
            conn.Close()
        End Try

        If tmpRoleNames.Length > 0 Then
            ' Remove trailing comma.
            tmpRoleNames = tmpRoleNames.Substring(0, tmpRoleNames.Length - 1)
            Return tmpRoleNames.Split(CChar(","))
        End If

        Return New String() {}
    End Function

    Public Overloads Function GetRolesForUser(ByVal username As String, ByVal programfk As Integer) As String()
        Dim tmpRoleNames As String = ""

        Dim conn As SqlConnection = New SqlConnection(connectionString)
        Dim cmd As SqlCommand = New SqlCommand("SELECT Rolename FROM UsersInRoles " &
                " WHERE Username = @Username AND ApplicationName = @ApplicationName " &
                " AND programsitefk = @ProgramSiteFK", conn)

        cmd.Parameters.Add("@Username", SqlDbType.VarChar, 255).Value = username
        cmd.Parameters.Add("@ApplicationName", SqlDbType.VarChar, 255).Value = ApplicationName
        cmd.Parameters.Add("@ProgramSiteFK", SqlDbType.Int).Value = programfk

        Dim reader As SqlDataReader = Nothing

        Try
            conn.Open()

            reader = cmd.ExecuteReader()

            Do While reader.Read()
                tmpRoleNames &= reader.GetString(0) & ","
            Loop
        Catch e As SqlException
            If WriteExceptionsToEventLog Then
                WriteToEventLog(e, "GetRolesForUser")
            Else
                Throw e
            End If
        Finally
            If Not reader Is Nothing Then reader.Close()
            conn.Close()
        End Try

        If tmpRoleNames.Length > 0 Then
            ' Remove trailing comma.
            tmpRoleNames = tmpRoleNames.Substring(0, tmpRoleNames.Length - 1)
            Return tmpRoleNames.Split(CChar(","))
        End If

        Return New String() {}
    End Function

    '
    ' RoleProvider.GetProgramsForUser
    '

    Public Function GetProgramsForUser(ByVal username As String) As String()
        Dim tmpRoleNames As String = ""

        Dim conn As SqlConnection = New SqlConnection(connectionString)
        Dim cmd As SqlCommand = New SqlCommand("SELECT DISTINCT programsitefk FROM UsersInRoles " &
                " WHERE Username = @Username AND ApplicationName = @ApplicationName order by leadagencyname", conn)

        cmd.Parameters.Add("@Username", SqlDbType.VarChar, 255).Value = username
        cmd.Parameters.Add("@ApplicationName", SqlDbType.VarChar, 255).Value = ApplicationName

        Dim reader As SqlDataReader = Nothing

        Try
            conn.Open()

            reader = cmd.ExecuteReader()

            Do While reader.Read()
                tmpRoleNames &= reader.GetInt32(0).ToString() & ","
            Loop
        Catch e As SqlException
            If WriteExceptionsToEventLog Then
                WriteToEventLog(e, "GetProgramsForUser")
            Else
                Throw e
            End If
        Finally
            If Not reader Is Nothing Then reader.Close()
            conn.Close()
        End Try

        If tmpRoleNames.Length > 0 Then
            ' Remove trailing comma.
            tmpRoleNames = tmpRoleNames.Substring(0, tmpRoleNames.Length - 1)
            Return tmpRoleNames.Split(CChar(","))
        End If

        Return New String() {}
    End Function

    Public Function GetProgramsByRole(ByVal username As String, ByVal role As String) As String()
        Dim tmpRoleNames As String = ""

        Dim conn As SqlConnection = New SqlConnection(connectionString)
        Dim cmd As SqlCommand = New SqlCommand("SELECT programsitefk FROM UsersInRoles " & "WHERE Username = @Username AND Rolename=@Rolename", conn)

        cmd.Parameters.Add("@Username", SqlDbType.VarChar, 255).Value = username
        cmd.Parameters.Add("@Rolename", SqlDbType.VarChar, 255).Value = role

        Dim reader As SqlDataReader = Nothing

        Try
            conn.Open()

            reader = cmd.ExecuteReader()

            Do While reader.Read()
                tmpRoleNames &= reader.GetInt32(0).ToString() & ","
            Loop
        Catch e As SqlException
            If WriteExceptionsToEventLog Then
                WriteToEventLog(e, "GetProgramsByRole")
            Else
                Throw e
            End If
        Finally
            If Not reader Is Nothing Then reader.Close()
            conn.Close()
        End Try

        If tmpRoleNames.Length > 0 Then
            ' Remove trailing comma.
            tmpRoleNames = tmpRoleNames.Substring(0, tmpRoleNames.Length - 1)
            Return tmpRoleNames.Split(CChar(","))
        End If

        Return New String() {}
    End Function

    '
    ' RoleProvider.GetUsersInRole
    '

    Public Overrides Function GetUsersInRole(ByVal rolename As String) As String()
        Dim tmpUserNames As String = ""

        Dim conn As SqlConnection = New SqlConnection(connectionString)
        Dim cmd As SqlCommand = New SqlCommand("SELECT Username FROM UsersInRoles " &
                  " WHERE Rolename = @Rolename AND ApplicationName = @ApplicationName", conn)

        cmd.Parameters.Add("@Rolename", SqlDbType.VarChar, 255).Value = rolename
        cmd.Parameters.Add("@ApplicationName", SqlDbType.VarChar, 255).Value = ApplicationName

        Dim reader As SqlDataReader = Nothing

        Try
            conn.Open()

            reader = cmd.ExecuteReader()

            Do While reader.Read()
                tmpUserNames &= reader.GetString(0) & ","
            Loop
        Catch e As SqlException
            If WriteExceptionsToEventLog Then
                WriteToEventLog(e, "GetUsersInRole")
            Else
                Throw e
            End If
        Finally
            If Not reader Is Nothing Then reader.Close()
            conn.Close()
        End Try

        If tmpUserNames.Length > 0 Then
            ' Remove trailing comma.
            tmpUserNames = tmpUserNames.Substring(0, tmpUserNames.Length - 1)
            Return tmpUserNames.Split(CChar(","))
        End If

        Return New String() {}
    End Function

    Public Overloads Function GetUsersInRole(ByVal rolename As String, ByVal programfk As Integer) As String()
        Dim tmpUserNames As String = ""

        Dim conn As SqlConnection = New SqlConnection(connectionString)
        Dim cmd As SqlCommand = New SqlCommand("SELECT Username FROM UsersInRoles " &
                  " WHERE Rolename = @Rolename AND ApplicationName = @ApplicationName " &
                  " AND programfk = @ProgramFK", conn)

        cmd.Parameters.Add("@Rolename", SqlDbType.VarChar, 255).Value = rolename
        cmd.Parameters.Add("@ApplicationName", SqlDbType.VarChar, 255).Value = ApplicationName
        cmd.Parameters.Add("@ProgramFK", SqlDbType.Int).Value = programfk

        Dim reader As SqlDataReader = Nothing

        Try
            conn.Open()

            reader = cmd.ExecuteReader()

            Do While reader.Read()
                tmpUserNames &= reader.GetString(0) & ","
            Loop
        Catch e As SqlException
            If WriteExceptionsToEventLog Then
                WriteToEventLog(e, "GetUsersInRole")
            Else
                Throw e
            End If
        Finally
            If Not reader Is Nothing Then reader.Close()
            conn.Close()
        End Try

        If tmpUserNames.Length > 0 Then
            ' Remove trailing comma.
            tmpUserNames = tmpUserNames.Substring(0, tmpUserNames.Length - 1)
            Return tmpUserNames.Split(CChar(","))
        End If

        Return New String() {}
    End Function

    '
    ' RoleProvider.GetUsersInProgram
    '

    Public Function GetUsersInProgram(ByVal programfk As Integer) As String()
        Dim tmpUserNames As String = ""

        Dim conn As SqlConnection = New SqlConnection(connectionString)
        Dim cmd As SqlCommand = New SqlCommand("SELECT Username FROM UsersInRoles " &
                  " WHERE programfk = @ProgramFK AND ApplicationName = @ApplicationName", conn)

        cmd.Parameters.Add("@ProgramFK", SqlDbType.Int).Value = programfk
        cmd.Parameters.Add("@ApplicationName", SqlDbType.VarChar, 255).Value = ApplicationName

        Dim reader As SqlDataReader = Nothing

        Try
            conn.Open()

            reader = cmd.ExecuteReader()

            Do While reader.Read()
                tmpUserNames &= reader.GetString(0) & ","
            Loop
        Catch e As SqlException
            If WriteExceptionsToEventLog Then
                WriteToEventLog(e, "GetUsersInProgram")
            Else
                Throw e
            End If
        Finally
            If Not reader Is Nothing Then reader.Close()
            conn.Close()
        End Try

        If tmpUserNames.Length > 0 Then
            ' Remove trailing comma.
            tmpUserNames = tmpUserNames.Substring(0, tmpUserNames.Length - 1)
            Return tmpUserNames.Split(CChar(","))
        End If

        Return New String() {}
    End Function

    '
    ' RoleProvider.GetUsersInProgramSite
    '

    Public Function GetUsersInProgramSite(ByVal programsitefk As Integer) As String()
        Dim tmpUserNames As String = ""

        Dim conn As SqlConnection = New SqlConnection(connectionString)
        Dim cmd As SqlCommand = New SqlCommand("SELECT Username FROM UsersInRoles " &
                  " WHERE ProgramSiteFK = @ProgramSiteFK AND ApplicationName = @ApplicationName", conn)

        cmd.Parameters.Add("@ProgramSiteFK", SqlDbType.Int).Value = programsitefk
        cmd.Parameters.Add("@ApplicationName", SqlDbType.VarChar, 255).Value = ApplicationName

        Dim reader As SqlDataReader = Nothing

        Try
            conn.Open()

            reader = cmd.ExecuteReader()

            Do While reader.Read()
                tmpUserNames &= reader.GetString(0) & ","
            Loop
        Catch e As SqlException
            If WriteExceptionsToEventLog Then
                WriteToEventLog(e, "GetUsersInProgram")
            Else
                Throw e
            End If
        Finally
            If Not reader Is Nothing Then reader.Close()
            conn.Close()
        End Try

        If tmpUserNames.Length > 0 Then
            ' Remove trailing comma.
            tmpUserNames = tmpUserNames.Substring(0, tmpUserNames.Length - 1)
            Return tmpUserNames.Split(CChar(","))
        End If

        Return New String() {}
    End Function


    '
    ' RoleProvider.IsUserInRole
    '

    Public Overrides Function IsUserInRole(ByVal username As String, ByVal rolename As String) As Boolean

        Dim userIsInRole As Boolean = False

        Dim conn As SqlConnection = New SqlConnection(connectionString)
        Dim cmd As SqlCommand = New SqlCommand("SELECT COUNT(*) FROM UsersInRoles " &
                                               " WHERE Username = @Username " &
                                               "AND Rolename = @Rolename AND ApplicationName = @ApplicationName", conn)

        cmd.Parameters.Add("@Username", SqlDbType.VarChar, 255).Value = username
        cmd.Parameters.Add("@Rolename", SqlDbType.VarChar, 255).Value = rolename
        cmd.Parameters.Add("@ApplicationName", SqlDbType.VarChar, 255).Value = ApplicationName

        Try
            conn.Open()

            Dim numRecs As Integer = CType(cmd.ExecuteScalar(), Integer)

            If numRecs > 0 Then
                userIsInRole = True
            End If
        Catch e As SqlException
            If WriteExceptionsToEventLog Then
                WriteToEventLog(e, "IsUserInRole")
            Else
                Throw e
            End If
        Finally
            conn.Close()
        End Try

        Return userIsInRole
    End Function

    '
    ' RoleProvider.IsUserInProgramSite
    '

    Public Function IsUserInProgramSite(ByVal username As String, ByVal programsitefk As Integer) As Boolean

        Dim userIsInRole As Boolean = False

        Dim conn As SqlConnection = New SqlConnection(connectionString)
        Dim cmd As SqlCommand = New SqlCommand("SELECT COUNT(*) FROM UsersInRoles " &
                " WHERE Username = @Username AND programsitefk = @ProgramSiteFK AND ApplicationName = @ApplicationName", conn)

        cmd.Parameters.Add("@Username", SqlDbType.VarChar, 255).Value = username
        cmd.Parameters.Add("@ProgramSiteFK", SqlDbType.Int).Value = programsitefk
        cmd.Parameters.Add("@ApplicationName", SqlDbType.VarChar, 255).Value = ApplicationName

        Try
            conn.Open()

            Dim numRecs As Integer = CType(cmd.ExecuteScalar(), Integer)

            If numRecs > 0 Then
                userIsInRole = True
            End If
        Catch e As SqlException
            If WriteExceptionsToEventLog Then
                WriteToEventLog(e, "IsUserInProgram")
            Else
                Throw e
            End If
        Finally
            conn.Close()
        End Try

        Return userIsInRole
    End Function

    '
    ' RoleProvider.IsUserInProgram
    '

    Public Function IsUserInProgram(ByVal username As String, ByVal programfk As Integer) As Boolean

        Dim userIsInRole As Boolean = False

        Dim conn As SqlConnection = New SqlConnection(connectionString)
        Dim cmd As SqlCommand = New SqlCommand("SELECT COUNT(*) FROM UsersInRoles " &
                " WHERE Username = @Username AND programfk = @ProgramFK AND ApplicationName = @ApplicationName", conn)

        cmd.Parameters.Add("@Username", SqlDbType.VarChar, 255).Value = username
        cmd.Parameters.Add("@ProgramFK", SqlDbType.Int).Value = programfk
        cmd.Parameters.Add("@ApplicationName", SqlDbType.VarChar, 255).Value = ApplicationName

        Try
            conn.Open()

            Dim numRecs As Integer = CType(cmd.ExecuteScalar(), Integer)

            If numRecs > 0 Then
                userIsInRole = True
            End If
        Catch e As SqlException
            If WriteExceptionsToEventLog Then
                WriteToEventLog(e, "IsUserInProgram")
            Else
                Throw e
            End If
        Finally
            conn.Close()
        End Try

        Return userIsInRole
    End Function

    '
    ' RoleProvider.RemoveUsersFromRoles
    '

    Public Overrides Sub RemoveUsersFromRoles(ByVal usernames As String(), ByVal rolenames As String())

        For Each rolename As String In rolenames
            If Not RoleExists(rolename) Then
                Throw New ProviderException("Role name not found.")
            End If
        Next

        For Each username As String In usernames
            For Each rolename As String In rolenames
                If Not IsUserInRole(username, rolename) Then
                    Throw New ProviderException("User is not in role.")
                End If
            Next
        Next

        Dim conn As SqlConnection = New SqlConnection(connectionString)
        Dim cmd As SqlCommand = New SqlCommand("DELETE FROM UsersInRoles " &
                " WHERE Username = @Username " &
                " AND Rolename = @Rolename " &
                " AND ApplicationName = @ApplicationName", conn)

        Dim userParm As SqlParameter = cmd.Parameters.Add("@Username", SqlDbType.VarChar, 255)
        Dim roleParm As SqlParameter = cmd.Parameters.Add("@Rolename", SqlDbType.VarChar, 255)
        cmd.Parameters.Add("@ApplicationName", SqlDbType.VarChar, 255).Value = ApplicationName

        Dim tran As SqlTransaction = Nothing

        Try
            conn.Open()
            tran = conn.BeginTransaction
            cmd.Transaction = tran

            For Each username As String In usernames
                For Each rolename As String In rolenames
                    userParm.Value = username
                    roleParm.Value = rolename
                    cmd.ExecuteNonQuery()
                Next
            Next

            tran.Commit()
        Catch e As SqlException
            Try
                tran.Rollback()
            Catch
            End Try


            If WriteExceptionsToEventLog Then
                WriteToEventLog(e, "RemoveUsersFromRoles")
            Else
                Throw e
            End If
        Finally
            conn.Close()
        End Try
    End Sub

    Public Overloads Sub RemoveUsersFromRoles(ByVal usernames As String(), ByVal rolenames As String(), ByVal programsitefk As Integer)

        For Each rolename As String In rolenames
            If Not RoleExists(rolename) Then
                Throw New ProviderException("Role name not found.")
            End If
        Next


        For Each username As String In usernames
            For Each rolename As String In rolenames
                If Not IsUserInRole(username, rolename) Then
                    Throw New ProviderException("User is not in role.")
                End If
            Next
        Next

        Dim conn As SqlConnection = New SqlConnection(connectionString)
        Dim cmd As SqlCommand = New SqlCommand("DELETE FROM UsersInRoles " &
                " WHERE Username = @Username AND Rolename = @Rolename AND ApplicationName = @ApplicationName " &
                " AND programsitefk = @ProgramSiteFK", conn)

        Dim userParm As SqlParameter = cmd.Parameters.Add("@Username", SqlDbType.VarChar, 255)
        Dim roleParm As SqlParameter = cmd.Parameters.Add("@Rolename", SqlDbType.VarChar, 255)
        cmd.Parameters.Add("@ApplicationName", SqlDbType.VarChar, 255).Value = ApplicationName
        cmd.Parameters.Add("@ProgramSiteFK", SqlDbType.Int).Value = programsitefk

        Dim tran As SqlTransaction = Nothing

        Try
            conn.Open()
            tran = conn.BeginTransaction
            cmd.Transaction = tran

            For Each username As String In usernames
                For Each rolename As String In rolenames
                    userParm.Value = username
                    roleParm.Value = rolename
                    cmd.ExecuteNonQuery()
                Next
            Next

            tran.Commit()
        Catch e As SqlException
            Try
                tran.Rollback()
            Catch
            End Try


            If WriteExceptionsToEventLog Then
                WriteToEventLog(e, "RemoveUsersFromRoles")
            Else
                Throw e
            End If
        Finally
            conn.Close()
        End Try
    End Sub


    '
    ' RoleProvider.RemoveUsersFromProgramSite
    '

    Public Sub RemoveUsersFromProgramSite(ByVal usernames As String(), ByVal programsitefk As Integer)

        For Each username As String In usernames
            If Not IsUserInProgramSite(username, programsitefk) Then
                Throw New ProviderException("User is not in program.")
            End If
        Next

        Dim conn As SqlConnection = New SqlConnection(connectionString)
        Dim cmd As SqlCommand = New SqlCommand("DELETE FROM UsersInRoles " &
                " WHERE Username = @Username AND programsitefk = @ProgramSiteFK AND ApplicationName = @ApplicationName", conn)

        Dim userParm As SqlParameter = cmd.Parameters.Add("@Username", SqlDbType.VarChar, 255)
        cmd.Parameters.Add("@ProgramSiteFK", SqlDbType.Int).Value = programsitefk
        cmd.Parameters.Add("@ApplicationName", SqlDbType.VarChar, 255).Value = ApplicationName

        Dim tran As SqlTransaction = Nothing

        Try
            conn.Open()
            tran = conn.BeginTransaction
            cmd.Transaction = tran

            For Each username As String In usernames
                userParm.Value = username
                cmd.ExecuteNonQuery()
            Next

            tran.Commit()
        Catch e As SqlException
            Try
                tran.Rollback()
            Catch
            End Try


            If WriteExceptionsToEventLog Then
                WriteToEventLog(e, "RemoveUsersFromProgram")
            Else
                Throw e
            End If
        Finally
            conn.Close()
        End Try
    End Sub


    '
    ' RoleProvider.RemoveUsersFromProgram
    '

    Public Sub RemoveUsersFromProgram(ByVal usernames As String(), ByVal programfk As Integer)

        For Each username As String In usernames
            If Not IsUserInProgram(username, programfk) Then
                Throw New ProviderException("User is not in program.")
            End If
        Next

        Dim conn As SqlConnection = New SqlConnection(connectionString)
        Dim cmd As SqlCommand = New SqlCommand("DELETE FROM UsersInRoles " &
                " WHERE Username = @Username AND programfk = @ProgramFK AND ApplicationName = @ApplicationName", conn)

        Dim userParm As SqlParameter = cmd.Parameters.Add("@Username", SqlDbType.VarChar, 255)
        cmd.Parameters.Add("@ProgramFK", SqlDbType.Int).Value = programfk
        cmd.Parameters.Add("@ApplicationName", SqlDbType.VarChar, 255).Value = ApplicationName

        Dim tran As SqlTransaction = Nothing

        Try
            conn.Open()
            tran = conn.BeginTransaction
            cmd.Transaction = tran

            For Each username As String In usernames
                userParm.Value = username
                cmd.ExecuteNonQuery()
            Next

            tran.Commit()
        Catch e As SqlException
            Try
                tran.Rollback()
            Catch
            End Try


            If WriteExceptionsToEventLog Then
                WriteToEventLog(e, "RemoveUsersFromProgram")
            Else
                Throw e
            End If
        Finally
            conn.Close()
        End Try
    End Sub

    '
    ' RoleProvider.RoleExists
    '

    Public Overrides Function RoleExists(ByVal rolename As String) As Boolean
        Dim exists As Boolean = False

        Dim conn As SqlConnection = New SqlConnection(connectionString)
        Dim cmd As SqlCommand = New SqlCommand("SELECT COUNT(*) FROM Roles " &
                  " WHERE Rolename = @Rolename AND ApplicationName = @ApplicationName", conn)

        cmd.Parameters.Add("@Rolename", SqlDbType.VarChar, 255).Value = rolename
        cmd.Parameters.Add("@ApplicationName", SqlDbType.VarChar, 255).Value = ApplicationName

        Try
            conn.Open()

            Dim numRecs As Integer = CType(cmd.ExecuteScalar(), Integer)

            If numRecs > 0 Then
                exists = True
            End If
        Catch e As SqlException
            If WriteExceptionsToEventLog Then
                WriteToEventLog(e, "RoleExists")
            Else
                Throw e
            End If
        Finally
            conn.Close()
        End Try

        Return exists
    End Function

    Public Overloads Function RoleExists(ByVal rolename As String, ByVal programfk As Integer) As Boolean
        Dim exists As Boolean = False

        Dim conn As SqlConnection = New SqlConnection(connectionString)
        Dim cmd As SqlCommand = New SqlCommand("SELECT COUNT(*) FROM Roles " &
                  " WHERE Rolename = @Rolename AND ApplicationName = @ApplicationName " &
                  " AND programfk = @ProgramFK", conn)

        cmd.Parameters.Add("@Rolename", SqlDbType.VarChar, 255).Value = rolename
        cmd.Parameters.Add("@ApplicationName", SqlDbType.VarChar, 255).Value = ApplicationName
        cmd.Parameters.Add("@ProgramFK", SqlDbType.Int).Value = programfk

        Try
            conn.Open()

            Dim numRecs As Integer = CType(cmd.ExecuteScalar(), Integer)

            If numRecs > 0 Then
                exists = True
            End If
        Catch e As SqlException
            If WriteExceptionsToEventLog Then
                WriteToEventLog(e, "RoleExists")
            Else
                Throw e
            End If
        Finally
            conn.Close()
        End Try

        Return exists
    End Function

    '
    ' RoleProvider.FindUsersInRole
    '

    Public Overrides Function FindUsersInRole(ByVal rolename As String, ByVal usernameToMatch As String) As String()

        Dim conn As SqlConnection = New SqlConnection(connectionString)
        Dim cmd As SqlCommand = New SqlCommand("SELECT Username FROM UsersInRoles  " &
                  "WHERE Username LIKE @UsernameSearch AND RoleName = @RoleName AND ApplicationName = @ApplicationName", conn)
        cmd.Parameters.Add("@UsernameSearch", SqlDbType.VarChar, 255).Value = usernameToMatch
        cmd.Parameters.Add("@RoleName", SqlDbType.VarChar, 255).Value = rolename
        cmd.Parameters.Add("@ApplicationName", SqlDbType.VarChar, 255).Value = pApplicationName

        Dim tmpUserNames As String = ""
        Dim reader As SqlDataReader = Nothing

        Try
            conn.Open()

            reader = cmd.ExecuteReader()

            Do While reader.Read()
                tmpUserNames &= reader.GetString(0) & ","
            Loop
        Catch e As SqlException
            If WriteExceptionsToEventLog Then
                WriteToEventLog(e, "FindUsersInRole")
            Else
                Throw e
            End If
        Finally
            If Not reader Is Nothing Then reader.Close()

            conn.Close()
        End Try

        If tmpUserNames.Length > 0 Then
            ' Remove trailing comma.
            tmpUserNames = tmpUserNames.Substring(0, tmpUserNames.Length - 1)
            Return tmpUserNames.Split(CChar(","))
        End If

        Return New String() {}
    End Function

    Public Overloads Function FindUsersInRole(ByVal rolename As String, ByVal usernameToMatch As String, ByVal programfk As Integer) As String()

        Dim conn As SqlConnection = New SqlConnection(connectionString)
        Dim cmd As SqlCommand = New SqlCommand("SELECT Username FROM UsersInRoles  " &
                  "WHERE Username LIKE @UsernameSearch AND RoleName = @RoleName AND ApplicationName = @ApplicationName " &
                  " AND programfk = @ProgramFK", conn)
        cmd.Parameters.Add("@UsernameSearch", SqlDbType.VarChar, 255).Value = usernameToMatch
        cmd.Parameters.Add("@RoleName", SqlDbType.VarChar, 255).Value = rolename
        cmd.Parameters.Add("@ApplicationName", SqlDbType.VarChar, 255).Value = pApplicationName
        cmd.Parameters.Add("@ProgramFK", SqlDbType.Int).Value = programfk

        Dim tmpUserNames As String = ""
        Dim reader As SqlDataReader = Nothing

        Try
            conn.Open()

            reader = cmd.ExecuteReader()

            Do While reader.Read()
                tmpUserNames &= reader.GetString(0) & ","
            Loop
        Catch e As SqlException
            If WriteExceptionsToEventLog Then
                WriteToEventLog(e, "FindUsersInRole")
            Else
                Throw e
            End If
        Finally
            If Not reader Is Nothing Then reader.Close()

            conn.Close()
        End Try

        If tmpUserNames.Length > 0 Then
            ' Remove trailing comma.
            tmpUserNames = tmpUserNames.Substring(0, tmpUserNames.Length - 1)
            Return tmpUserNames.Split(CChar(","))
        End If

        Return New String() {}
    End Function

    '
    ' RoleProvider.FindUsersInProgram
    '

    Public Function FindUsersInProgram(ByVal programfk As Integer, ByVal usernameToMatch As String) As String()

        Dim conn As SqlConnection = New SqlConnection(connectionString)
        Dim cmd As SqlCommand = New SqlCommand("SELECT Username FROM UsersInRoles  " &
                  "WHERE Username LIKE @UsernameSearch AND programfk = @ProgramFK AND ApplicationName = @ApplicationName", conn)
        cmd.Parameters.Add("@UsernameSearch", SqlDbType.VarChar, 255).Value = usernameToMatch
        cmd.Parameters.Add("@ProgramFK", SqlDbType.Int).Value = programfk
        cmd.Parameters.Add("@ApplicationName", SqlDbType.VarChar, 255).Value = pApplicationName

        Dim tmpUserNames As String = ""
        Dim reader As SqlDataReader = Nothing

        Try
            conn.Open()

            reader = cmd.ExecuteReader()

            Do While reader.Read()
                tmpUserNames &= reader.GetString(0) & ","
            Loop
        Catch e As SqlException
            If WriteExceptionsToEventLog Then
                WriteToEventLog(e, "FindUsersInProgram")
            Else
                Throw e
            End If
        Finally
            If Not reader Is Nothing Then reader.Close()

            conn.Close()
        End Try

        If tmpUserNames.Length > 0 Then
            ' Remove trailing comma.
            tmpUserNames = tmpUserNames.Substring(0, tmpUserNames.Length - 1)
            Return tmpUserNames.Split(CChar(","))
        End If

        Return New String() {}
    End Function

    '
    ' WriteToEventLog
    '   A helper function that writes exception detail to the event log. Exceptions
    ' are written to the event log as a security measure to aSub Private database
    ' details from being returned to the browser. If a method does not Return a status
    ' or boolean indicating the action succeeded or failed, a generic exception is also 
    ' Thrown by the caller.
    '

    Private Sub WriteToEventLog(ByVal e As SqlException, ByVal action As String)
        Dim log As EventLog = New EventLog()
        log.Source = eventSource
        log.Log = eventLog

        Dim message As String = exceptionMessage & vbCrLf & vbCrLf
        message &= "Action: " & action & vbCrLf & vbCrLf
        message &= "Exception: " & e.ToString()

        log.WriteEntry(message)
    End Sub

End Class