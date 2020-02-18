import { Resolver, Query, Mutation, Arg, ObjectType, Field, Ctx, UseMiddleware, Int } from 'type-graphql'
import { User } from './entity/User'
import { hash, compare } from 'bcrypt'
import { MyContext } from './MyContext'
import { createRefreshToken, createAccessToken } from './auth'
import { isAuth } from './isAuth'
import { sendRefreshToken } from './sendRefreshToken'
import { getConnection } from 'typeorm'

@ObjectType()
class LoginResponse {
  @Field()
  accessToken: string
}

@Resolver()
export class UserResolver {
  // get all users
  @Query(() => [User])
  users() {
    return User.find()
  }

  // get authorized data
  @Query(() => String)
  @UseMiddleware(isAuth)
  authorized(@Ctx() { payload }: MyContext) {
    console.log(payload)
    return `your user id is ${payload!.userId}`
  }

  // register new user
  @Mutation(() => Boolean)
    async register(
      @Arg('email') email: string,
      @Arg('password') password: string
    ) {

      const hashedPassword = await hash(password, 12)

      try {
        await User.insert({
          email,
          password: hashedPassword
        })
      } catch (err) {
        console.log(err)
        return false
      }
      return true
    }

  // login user
  @Mutation(() => LoginResponse)
  async login(
    @Arg('email') email: string,
    @Arg('password') password: string,
    @Ctx() { res }: MyContext
  ): Promise<LoginResponse> {
    const user = await User.findOne({ where: { email } })

    if (!user) {
      throw new Error('could not find user')
    }

    const valid = await compare(password, user.password)

    if (!valid) {
      throw new Error('invalid password')
    }

    // login successful
    sendRefreshToken(res, createRefreshToken(user))

    return {
      accessToken: createAccessToken(user)
    }
  }

  // for test purposes only
  // revoke user refresh token
  @Mutation(() => Boolean)
  async revokeRefreshTokensForUser(@Arg('userId', () => Int) userId: number) {
    await getConnection()
      .getRepository(User)
      .increment({ id: userId }, 'tokenVersion', 1)

    return true
  }
}
