<?php


namespace DongFie\JWT;
use think\facade\Cache;

class JWTAuth extends JWT
{

    /**
     * 创建token
     * @param $model
     * @param $data
     * @return false|string
     */
    public static function createToken($model, $data)
    {
        if (empty($data) || empty($model)) {
            return ['code' => -1, 'message' => "参数不能为空"];
        }
        //获取用户标识
        $identifier = config('jwt.identifier');
        $key        = config('jwt.key');
        $getUser    = $model->where($identifier, '=', $data[$identifier])->find();

        if (empty($getUser)) {
            return ['code' => -1, 'message' => '无法生成token'];
        }
        $token = [
            'iss'  => config('jwt.iss'), //签发者 可选
            'aud'  => config('jwt.aud'), //接收该JWT的一方，可选
            'iat'  => config('jwt.iat'), //签发时间
            'nbf'  => config('jwt.nbf'), //(Not Before)：某个时间点后才能访问，比如设置time+30，表示当前时间30秒后才能使用
            'exp'  => config('jwt.exp'), //过期时间,这里设置2个小时
            'data' => $data
        ];
        return ['code' => 1, 'message' => JWT::encode($token, $key)];

    }

    /**
     * 验证token
     * @param $token
     * @return false|string
     */
    public static function validateToken($token)
    {

        $key = config('jwt.key');
        try {
            JWT::$leeway = 60;
            $tokenInfo   = JWT::decode($token, $key, config('jwt.algorithms'));
            return ['code' => 1, 'message' => $tokenInfo];
        } catch (SignatureInvalidException $e) {//签名不正确
            return ['code' => -1, 'message' => $e->getMessage()];
        } catch (BeforeValidException $e) {//签名在某个时间点之后才能用
            return ['code' => -1, 'message' => $e->getMessage()];
        } catch (ExpiredException $e) {//token过期
            return ['code' => -1, 'message' => $e->getMessage()];
        } catch (\Exception $e) {//其他错误
            return ['code' => -1, 'message' => $e->getMessage()];
        }
    }

    /**
     * 通过TOKEN获取用户的信息
     * @return \think\response\Json
     */
    public static function tokenGetUser()
    {
        $key = config('jwt.key');
        //获取用户标识
        $identifier = config('jwt.identifier');
        $authorization = explode(' ', $_SERVER['HTTP_AUTHORIZATION'])[1];
        try {
            JWT::$leeway = 60;
            $decoded = JWT::decode($authorization, $key, ['HS256']);
            $getTokenUser = Cache::get('memberInfo:' . $decoded->data->$identifier);
            if (!$getTokenUser) {
                return json(array('code' => -2, 'message' => 'token not find'));
            }
            //判断账号密码
            $unserialize = unserialize($getTokenUser);
            return json($unserialize);
        } catch (\Firebase\JWT\SignatureInvalidException $e) {  //签名不正确
            return json(array('code' => -2, 'message' => $e->getMessage()));
        } catch (\Firebase\JWT\BeforeValidException $e) {  // 签名在某个时间点之后才能用
            return json(array('code' => -2, 'message' => $e->getMessage()));
        } catch (\Firebase\JWT\ExpiredException $e) {  // token过期
            return json(array('code' => -2, 'message' => $e->getMessage()));
        } catch (\Exception $e) {  //其他错误
            return json(array('code' => -2, 'message' => $e->getMessage()));
        }
    }
}
