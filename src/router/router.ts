import {Router} from "express";
import {authMiddleware} from "../middleware/auth";
import {isErrorMiddleware} from "../middleware/catch-error";
import {BlogController} from "../controllers/blog-controller";
import {PostController} from "../controllers/post-controller";
import {UserController} from "../controllers/user-controller";
import {AuthController} from "../controllers/auth-controller";
import {TestController} from "../controllers/testing-controller";
import {basicAuthorization} from "../authorizations/authorization";
import {CommentController} from "../controllers/comment-controller";
import {
    blogValidation, codeConfirmed,
    commentValidation, emailExistValidation,
    postValidation,
    postValidationWithoutBodyId,
    userValidation
} from "../validator/validator";

export const router = Router();

/**Test**/
router.delete('/testing/all-data', TestController.testing);

/**Blogs**/
router.get('/blogs', BlogController.getAllBlogs);
router.post('/blogs', basicAuthorization, blogValidation, isErrorMiddleware, BlogController.createBlog);
router.get('/blogs/:id', BlogController.getOneBlog);
router.put('/blogs/:id', basicAuthorization, blogValidation, isErrorMiddleware, BlogController.updateBlog);
router.delete('/blogs/:id', basicAuthorization, BlogController.deleteBlog);
router.get('/blogs/:blogId/posts', BlogController.getAllPostsForTheBlog);
router.post('/blogs/:blogId/posts', basicAuthorization, postValidationWithoutBodyId, isErrorMiddleware, BlogController.createPostTheBlog);

/**Posts**/
router.get('/posts', PostController.getAllPosts);
router.post('/posts', basicAuthorization, postValidation, isErrorMiddleware, PostController.createPost);
router.get('/posts/:id', PostController.getOnePost);
router.put('/posts/:id', basicAuthorization, postValidation, isErrorMiddleware, PostController.updatePost);
router.delete('/posts/:id', basicAuthorization, PostController.deletePost);
router.get('/posts/:postId/comments', PostController.getAllCommentsForThePost);
router.post('/posts/:postId/comments', authMiddleware, commentValidation, isErrorMiddleware, PostController.createCommentThePost);

/**Users**/
router.get('/users', basicAuthorization, UserController.getAllUsers);
router.post('/users', basicAuthorization, userValidation, isErrorMiddleware, UserController.createUser);
router.delete('/users/:id', basicAuthorization, UserController.deleteUser);

/**Comments**/
router.put('/comments/:commentId', authMiddleware, commentValidation, isErrorMiddleware, CommentController.updateComment);
router.delete('/comments/:id', authMiddleware, CommentController.deleteComment);
router.get('/comments/:id', CommentController.getOneComment);

/**Auth**/
router.post('/auth/login', AuthController.login);
router.post('/auth/registration-confirmation', codeConfirmed, codeConfirmed, isErrorMiddleware, AuthController.confirmEmail);
router.post('/auth/registration', userValidation, isErrorMiddleware, AuthController.registration);
router.post('/auth/registration-email-resending', emailExistValidation, isErrorMiddleware, AuthController.resendConfirm);
router.get('/auth/me', authMiddleware, isErrorMiddleware, AuthController.me);