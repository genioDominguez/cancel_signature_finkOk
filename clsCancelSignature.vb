'Importamos las siguentes clases necesarias.
Imports System.Text
Imports System.Xml
Imports System.Security
Imports System.Security.Cryptography
Imports System.Security.Cryptography.Xml
Imports TestFinkok.cancelaFinkok
Imports JavaScience.opensslkey
''' <summary>
''' Esta clase hace una cancelación de un CFDi utilizando el método Cancel_signature
''' </summary>
''' <remarks></remarks>

Public Class clsCancelSignature
    ''' <summary>
    ''' Método para cancelar
    ''' </summary>
    ''' <param name="UUid">Indique el UUiD del CFDi</param>
    ''' <param name="Emisor">Indique el RFC del emisor del CFDi</param>
    ''' <param name="Fecha">Indique la Fecha de emisión del CFDi</param>
    ''' <remarks></remarks>
    ''' Este ejemplo supone que los archivos del certificado y llave privada se encuentran en el directorio raiz del disco C
    ''' tambien supone que tiene permisos de escritura en el directorio raiz del disco C ya que ahí coloca el resultado de la cancelación
    ''' 
    Public Sub CancelaCFDi(UUid As String, Emisor As String, Fecha As Date)

        Dim X509IssuerName As String 'variable donde almacenaremos el Nombre del emisor del certificado
        Dim X509SerialNumber As String 'variable donde almacenaremos el Numero de serie del certificado

        'Primero formamos el XML con la información del CFDi a cancelar
        Dim XmlDoc As New XmlDocument
        XmlDoc.LoadXml("<Cancelacion xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"" xmlns=""http://cancelacfd.sat.gob.mx"" RfcEmisor=""" & Emisor & """ Fecha=""" & Fecha.ToString("yyyy-MM-ddTHH:mm:ss") & """> " &
                        "   <Folios>" &
                        "       <UUID>" & UUid & "</UUID>" &
                        "   </Folios>" &
                        "</Cancelacion>")

        'Abrimos el archivo de la llave privada para convertirlo en Bytes que es como se requiere para desencriptarlo
        Dim fs As New System.IO.FileStream("C:\aad990814bp7_1210261233s.key", System.IO.FileMode.Open, System.IO.FileAccess.Read)
        Dim ImageData As Byte() = New Byte(fs.Length - 1) {}
        fs.Read(ImageData, 0, System.Convert.ToInt32(fs.Length))
        fs.Close()
        'Pasamos la contraseña de la llave privada a un objeto SecureString
        Dim passwordSeguro As New System.Security.SecureString()
        passwordSeguro.Clear()
        For Each c As Char In "12345678a".ToCharArray()
            passwordSeguro.AppendChar(c)
        Next
        'Creamos el Objeto RSA para la firma
        Dim rsa As System.Security.Cryptography.RSACryptoServiceProvider = DecodeEncryptedPrivateKeyInfo(ImageData, passwordSeguro)
        Dim parRsa As System.Security.Cryptography.RSAParameters = rsa.ExportParameters(True)

        'obtenemos los datos del certificado 
        Dim Cert As System.Security.Cryptography.X509Certificates.X509Certificate = Cryptography.X509Certificates.X509Certificate.CreateFromCertFile("C:\aad990814bp7_1210261233s.cer")
        Dim kdata As New KeyInfoX509Data(Cert)
        Dim xserial As X509IssuerSerial
        X509SerialNumber = StrReverse(System.Text.Encoding.ASCII.GetString(Cert.GetSerialNumber))
        X509IssuerName = RemoveAcentos(Cert.Issuer) ' es necesario remover los acentos del nombre del emisor ya que esto causa un error
        xserial.IssuerName = X509IssuerName
        xserial.SerialNumber = X509SerialNumber
        kdata.AddIssuerSerial(xserial.IssuerName, xserial.SerialNumber)

        'Creamos el objeto XML con el que se realizará el proceso de la firma
        Dim sxmlD As New SignedXml(XmlDoc)
        sxmlD.SigningKey = rsa

        'crea un objeto que contendrá la información del certificado y la llave
        Dim keyInfo As New KeyInfo()
        'agregamos los datos del certificado
        keyInfo.AddClause(kdata)
        'agregamos los datos de la llave
        keyInfo.AddClause(New RSAKeyValue(CType(rsa, RSA)))
        'Agregarmos la información de la llave al xml
        sxmlD.KeyInfo = keyInfo

        'firmamos el xml
        sxmlD.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigCanonicalizationUrl
        Dim r As Reference = New Reference("")
        r.AddTransform(New XmlDsigEnvelopedSignatureTransform(False))
        sxmlD.AddReference(r)
        sxmlD.ComputeSignature()
        Dim sig As XmlElement = sxmlD.GetXml()

        'agregamos la firma a nuestro xml original
        XmlDoc.DocumentElement.AppendChild(sig)

        'Ahora consumimos el web service 
        Dim can As New cancel_signature
        can.username = "TuUsuarioFinkOk"
        can.password = "TuPassWordFinkok"
        can.xml = stringToBase64ByteArray(XmlDoc.OuterXml) 'El archivo XML se envia en Base64.
        Dim cancelado As New CancelSOAP
        Dim ResponseCancel As New cancel_signatureResponse
        ResponseCancel = cancelado.cancel_signature(can)
        Dim statusUUID As String
        statusUUID = ResponseCancel.cancel_signatureResult.CodEstatus
        Dim fechaCancela = ResponseCancel.cancel_signatureResult.Fecha
        Dim acuse = ResponseCancel.cancel_signatureResult.Acuse
        Dim RFCemisor = ResponseCancel.cancel_signatureResult.RfcEmisor

        'Finalmente guardamos el acuse en un archivo XML en el directorio Raíz del disco C:
        System.IO.File.WriteAllText("c:\acuse_signature.xml", acuse)
    End Sub
    Private Shared Function RemoveAcentos(stIn As String) As String
        Dim stFormD As String = stIn.Normalize(NormalizationForm.FormD)
        Dim sb As New StringBuilder()
        For ich As Integer = 0 To stFormD.Length - 1
            Dim uc As Globalization.UnicodeCategory = Globalization.CharUnicodeInfo.GetUnicodeCategory(stFormD(ich))
            If uc <> Globalization.UnicodeCategory.NonSpacingMark Then
                sb.Append(stFormD(ich))
            End If
        Next
        Return (sb.ToString().Normalize(NormalizationForm.FormC))
    End Function
    Private Function stringToBase64ByteArray(ByVal input As String) As Byte()
        Dim ret As Byte() = Encoding.UTF8.GetBytes(input)
        Dim s As String = Convert.ToBase64String(ret)
        ret = Convert.FromBase64String(s)
        Return ret
    End Function

End Class
