import { PrismaClient, User } from '@prisma/client';
import { CreateUserDto } from '@dtos/users.dto';
import { HttpException } from '@exceptions/HttpException';
import { isEmpty } from '@utils/util';
import { generateRandomSalt, passwordHash } from '@/utils/crypto';

class UserService {
  public users = new PrismaClient().user;

  public async findAllUser(): Promise<User[]> {
    const allUser: User[] = await this.users.findMany();
    return allUser;
  }

  public async findUserById(userId: number): Promise<User> {
    if (isEmpty(userId)) throw new HttpException(400, "Empty fields");

    const findUser: User = await this.users.findUnique({ where: { id: userId } });
    if (!findUser) throw new HttpException(409, "User does not exist");

    return findUser;
  }

  public async createUser(userData: CreateUserDto): Promise<User> {
    if (isEmpty(userData)) throw new HttpException(400, "Empty fields");

    const findUser: User = await this.users.findUnique({ where: { email: userData.email } });
    if (findUser) throw new HttpException(401, `The email already exists`);
    const hash = await generateRandomSalt()
    const password = await passwordHash(userData.password, hash)
    const createUserData: User = await this.users.create({ data: { ...userData, password: password, passwordHash: hash } });
    return createUserData;
  }

  public async updateUser(userId: number, userData: CreateUserDto): Promise<User> {
    if (isEmpty(userData)) throw new HttpException(400, "Empty fields");

    const findUser: User = await this.users.findUnique({ where: { id: userId } });
    if (!findUser) throw new HttpException(409, "User does not exist");
    const hash = await generateRandomSalt()
    const password = await passwordHash(userData.password, hash)
    const updateUserData = await this.users.update({ where: { id: userId }, data: { ...userData, password: password, passwordHash: hash } });
    return updateUserData;
  }

  public async deleteUser(userId: number): Promise<User> {
    if (isEmpty(userId)) throw new HttpException(400, "Empty fields");

    const findUser: User = await this.users.findUnique({ where: { id: userId } });
    if (!findUser) throw new HttpException(409, "User does not exist");

    const deleteUserData = await this.users.delete({ where: { id: userId } });
    return deleteUserData;
  }
}

export default UserService;
