import com.amazonaws.secretsmanager.caching.SecretCache;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.json.JSONObject;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Map;

public class KeyGen implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private final static SecretCache cache = new SecretCache();

    @Override
    public APIGatewayProxyResponseEvent handleRequest(APIGatewayProxyRequestEvent input, Context context) {
        String responseBody = "";
        int statusCode = 200;

        try {
            context.getLogger().log("Received request: " + input);

            String secrets = cache.getSecretString("arn:aws:secretsmanager:us-east-1:967162346775:secret:SP-APP-KeyGen-TCVdEU");
            JSONObject o = new JSONObject(secrets);
            String pubKey = o.get("sp-app-keygen-pubKey").toString();
            String privKey = o.get("sp-app-keygen-privKey").toString();
            String token = o.get("sp-app-keygen-token").toString();

            // Verify we have all secrets
            if (pubKey == null || pubKey.isEmpty() ||
                privKey == null || privKey.isEmpty() ||
                token == null || token.isEmpty())
            {
                context.getLogger().log("Missing secrets!");
                APIGatewayProxyResponseEvent response = new APIGatewayProxyResponseEvent();
                response.setStatusCode(500);
                response.setBody("Failed to setup.");
                return response;
            }

            Map<String, String> inputParams = input.getQueryStringParameters();
            String requestToken = inputParams.get("token");
            if (requestToken.equals(token)) {
                String id = inputParams.get("id");
                String sites = inputParams.get("sites");
                String expires = inputParams.get("expires");

                if (id != null && !id.isEmpty() &&
                    sites != null && !sites.isEmpty() &&
                    expires != null && !expires.isEmpty())
                {
                    for (String site : sites.split("\\s*,\\s*")) {
                        String key = sign(id + "--" + site + "--" + expires, pubKey, privKey);

                        responseBody += "partner: {\n";
                        responseBody += "  id: '" + id + "',\n";
                        responseBody += "  site: '" + site + "',\n";
                        responseBody += "  key: '" + key + "',\n";
                        responseBody += "  expires: " + expires + "\n";
                        responseBody += "}\n\n";
                    }
                }
                else {
                    responseBody = "Missing one or more required args - id, sites, expires";
                    statusCode = 400;
                }
            }
            else {
                responseBody = "Access Denied - Incorrect token";
                statusCode = 401;
            }
        } catch (Exception e) {
            StringWriter sw = new StringWriter();
            e.printStackTrace(new PrintWriter(sw));
            String exceptionAsString = sw.toString();

            responseBody = exceptionAsString;
            statusCode = 500;
        }

        context.getLogger().log("Response status: " + statusCode);
        context.getLogger().log("Response body: " + responseBody);

        APIGatewayProxyResponseEvent response = new APIGatewayProxyResponseEvent();
        response.setStatusCode(statusCode);
        response.setBody(responseBody);
        return response;
    }

    private static String sign(String data, String pub, String priv) throws Exception {
        Base64.Decoder decoder = Base64.getDecoder();

        byte[] pkBytes = decoder.decode(priv);

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pkBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("DSA");
        PrivateKey privKey = keyFactory.generatePrivate(keySpec);

        /* Create a Signature object and initialize it with the private key */
        Signature dsa = Signature.getInstance("SHA1withDSA", "SUN");
        dsa.initSign(privKey);

        /* Update and sign the data */
        dsa.update(data.getBytes());

        /* Now that all the data to be signed has been read in generate a signature for it */
        byte[] sigBytes = dsa.sign();

        // Make sure it works
        pkBytes = decoder.decode(pub);
        KeySpec pubKeySpec = new X509EncodedKeySpec(pkBytes);
        PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);

        Signature sigVerifty = Signature.getInstance("SHA1withDSA", "SUN");
        sigVerifty.initVerify(pubKey);
        sigVerifty.update(data.getBytes());
        if (!sigVerifty.verify(sigBytes)) {
            throw new Exception("Failed to verify sig after signing!");
        }

        /* Output sig */
        Base64.Encoder encoder = Base64.getEncoder();
        byte[] sig = encoder.encode(sigBytes);

        return new String(sig);
    }
}
